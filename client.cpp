#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include "protocol.h"
#include <thread>
#include <atomic>
#include <fstream>
#include <string>
#include <map>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <mutex>
#include <iphlpapi.h>
#include <conio.h>

// You must download wintun.h from the official Wintun repository and include it in your project folder
#include "wintun.h" 

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

// Dynamic Wintun API Pointers
static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter;
static WINTUN_START_SESSION_FUNC* WintunStartSession;
static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC* WintunSendPacket;
static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter;
static WINTUN_END_SESSION_FUNC* WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent;
static HMODULE wintun_module = NULL;
static HANDLE stop_event = NULL;
static HANDLE cleanup_done = NULL;
static bool route1_added = false, route2_added = false, server_route_added = false;
static std::string server_route_delete;
std::atomic<uint64_t> tx_errors(0), rx_errors(0), invalid_packets(0);
std::atomic<uint64_t> tx_invalid(0);
std::atomic<int> last_send_error(0);

std::atomic<bool> keepRunning(true);
WINTUN_ADAPTER_HANDLE adapter = NULL;
WINTUN_SESSION_HANDLE session = NULL;
SOCKET udp_socket = INVALID_SOCKET;
char auth_header[8] = {0};
std::string server_ip_str;
std::string tun_name_str;

std::atomic<uint64_t> tx_bytes(0);
std::atomic<uint64_t> rx_bytes(0);
std::atomic<int> current_ping(-1);
std::atomic<int64_t> last_ping_reply(0);

std::string format_bytes(uint64_t bytes) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(2);
    if (bytes >= 1024ULL * 1024 * 1024)
        out << (bytes / (1024.0 * 1024 * 1024)) << " GB";
    else if (bytes >= 1024 * 1024)
        out << (bytes / (1024.0 * 1024)) << " MB";
    else if (bytes >= 1024)
        out << (bytes / 1024.0) << " KB";
    else
        out << bytes << " B";
    return out.str();
}

std::string format_bits_per_sec(uint64_t bytes_per_sec) {
    uint64_t bits = bytes_per_sec * 8;
    std::ostringstream out;
    out << std::fixed << std::setprecision(2);
    if (bits >= 1000ULL * 1000 * 1000)
        out << (bits / (1000.0 * 1000 * 1000)) << " Gbps";
    else if (bits >= 1000 * 1000)
        out << (bits / (1000.0 * 1000)) << " Mbps";
    else if (bits >= 1000)
        out << (bits / 1000.0) << " Kbps";
    else
        out << bits << " bps";
    return out.str();
}

std::map<std::string, std::string> parse_config(const std::string& filename) {
    std::map<std::string, std::string> config;
    std::ifstream file(filename);
    if (!file) throw std::runtime_error("Cannot open configuration: " + filename);
    std::string line;
    while (std::getline(file, line)) {
        size_t comment = line.find('#');
        if (comment != std::string::npos) line = line.substr(0, comment);
        size_t eq = line.find('=');
        if (eq != std::string::npos) {
            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t\r") + 1);
            if (val.find_first_not_of(" \t\r") == std::string::npos) val.clear();
            if (!val.empty()) {
                val.erase(0, val.find_first_not_of(" \t"));
                val.erase(val.find_last_not_of(" \t\r") + 1);
            }
            config[key] = val;
        }
    }
    return config;
}

// Graceful cleanup on Ctrl+C or terminal close
std::mutex cleanup_mutex;

void CleanupTunnel() {
    std::lock_guard<std::mutex> lock(cleanup_mutex);
    keepRunning = false;

    // Remove VPN routes BEFORE closing the adapter so we don't get "Element not found"
    if (route1_added)
        system(("netsh interface ipv4 delete route 0.0.0.0/1 \"" + tun_name_str + "\" >nul 2>&1").c_str());
    if (route2_added)
        system(("netsh interface ipv4 delete route 128.0.0.0/1 \"" + tun_name_str + "\" >nul 2>&1").c_str());
    if (server_route_added) system(server_route_delete.c_str());
    route1_added = route2_added = server_route_added = false;

    if (session) {
        WintunEndSession(session);
        session = NULL;
    }
    if (adapter) { WintunCloseAdapter(adapter); adapter = NULL; }
    if (udp_socket != INVALID_SOCKET) { closesocket(udp_socket); udp_socket = INVALID_SOCKET; }

    WSACleanup();
    // Event handles live until process exit to remain valid for the console handler.
    if (wintun_module) { FreeLibrary(wintun_module); wintun_module = NULL; }
    if (cleanup_done) SetEvent(cleanup_done);
}

BOOL WINAPI ConsoleCleanupHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT) {
        keepRunning = false;
        if (stop_event) SetEvent(stop_event);
        if (dwCtrlType == CTRL_CLOSE_EVENT && cleanup_done) WaitForSingleObject(cleanup_done, 4000);
        return TRUE;
    }
    return FALSE;
}

bool InitializeWintun() {
    HMODULE wintun = LoadLibraryA("wintun.dll");
    if (!wintun) return false;
    wintun_module = wintun;
    
    WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC*)GetProcAddress(wintun, "WintunCreateAdapter");
    WintunStartSession = (WINTUN_START_SESSION_FUNC*)GetProcAddress(wintun, "WintunStartSession");
    WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC*)GetProcAddress(wintun, "WintunReceivePacket");
    WintunReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC*)GetProcAddress(wintun, "WintunReleaseReceivePacket");
    WintunAllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC*)GetProcAddress(wintun, "WintunAllocateSendPacket");
    WintunSendPacket = (WINTUN_SEND_PACKET_FUNC*)GetProcAddress(wintun, "WintunSendPacket");
    WintunCloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC*)GetProcAddress(wintun, "WintunCloseAdapter");
    WintunEndSession = (WINTUN_END_SESSION_FUNC*)GetProcAddress(wintun, "WintunEndSession");
    WintunGetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC*)GetProcAddress(wintun, "WintunGetReadWaitEvent");
    return WintunCreateAdapter && WintunStartSession && WintunReceivePacket &&
        WintunReleaseReceivePacket && WintunAllocateSendPacket && WintunSendPacket &&
        WintunCloseAdapter && WintunEndSession && WintunGetReadWaitEvent;
}

void WintunToUdpThread(sockaddr_in server_addr) {
    (void)server_addr;
    HANDLE waits[] = {stop_event, WintunGetReadWaitEvent(session)};
    while (keepRunning) {
        DWORD packetSize;
        BYTE* packet = WintunReceivePacket(session, &packetSize);
        if (packet) {
            if (rawtun::valid_ipv4(reinterpret_cast<char*>(packet), packetSize)) {
                WSABUF buffers[2] = {{8, auth_header}, {packetSize, reinterpret_cast<char*>(packet)}};
                DWORD sent = 0;
                if (WSASend(udp_socket, buffers, 2, &sent, 0, NULL, NULL) == 0 && sent == packetSize + 8)
                    tx_bytes.fetch_add(packetSize, std::memory_order_relaxed);
                else {
                    last_send_error = WSAGetLastError();
                    tx_errors.fetch_add(1, std::memory_order_relaxed);
                }
            } else tx_invalid.fetch_add(1, std::memory_order_relaxed);
            WintunReleaseReceivePacket(session, packet);
        } else {
            DWORD error = GetLastError();
            if (error != ERROR_NO_MORE_ITEMS) {
                ++tx_errors;
                keepRunning = false;
                SetEvent(stop_event);
                break;
            }
            DWORD result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (result != WAIT_OBJECT_0 + 1) {
                keepRunning = false;
                SetEvent(stop_event);
                break;
            }
        }
    }
}

void UdpToWintunThread() {
    char buffer[65535];
    while (keepRunning) {
        int nread = recvfrom(udp_socket, buffer, sizeof(buffer), 0, NULL, NULL);
        if (nread == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAETIMEDOUT || error == WSAEWOULDBLOCK) continue;
            ++rx_errors;
            if (error == WSAEMSGSIZE || error == WSAECONNRESET) continue;
            keepRunning = false;
            SetEvent(stop_event);
            break;
        }
        if (nread >= 8) {
            if (memcmp(buffer, auth_header, 8) == 0) {
                if (nread == 16) {
                    // Ping echo received
                    int64_t sent_time;
                    memcpy(&sent_time, buffer + 8, 8);
                    auto now = std::chrono::steady_clock::now().time_since_epoch();
                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
                    if (sent_time > now_ms || now_ms - sent_time > 60000) { ++invalid_packets; continue; }
                    current_ping = static_cast<int>(now_ms - sent_time);
                    last_ping_reply = now_ms;
                } else if (nread > 8) {
                    if (!rawtun::valid_ipv4(buffer + 8, nread - 8)) {
                        ++invalid_packets;
                        continue;
                    }
                    BYTE* packet = WintunAllocateSendPacket(session, nread - 8);
                    if (packet) {
                        memcpy(packet, buffer + 8, nread - 8);
                        WintunSendPacket(session, packet);
                        rx_bytes.fetch_add(nread - 8, std::memory_order_relaxed);
                    } else ++rx_errors;
                }
            } else ++invalid_packets;
        } else ++invalid_packets;
    }
}

void KeepAliveThread(sockaddr_in server_addr, bool enable_stats) {
    (void)server_addr;
    char ping_packet[16];
    memcpy(ping_packet, auth_header, 8);
    
    uint64_t last_tx = 0;
    uint64_t last_rx = 0;
    auto last_sample = std::chrono::steady_clock::now();

    while (keepRunning) {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        int64_t timestamp = now_ms;
        memcpy(ping_packet + 8, &timestamp, 8);
        
        if (send(udp_socket, ping_packet, 16, 0) != 16) { last_send_error = WSAGetLastError(); ++tx_errors; }
        
        if (enable_stats) {
            uint64_t current_tx = tx_bytes.load();
            uint64_t current_rx = rx_bytes.load();
            auto sample = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(sample - last_sample).count();
            uint64_t tx_speed = elapsed > 0 ? static_cast<uint64_t>((current_tx - last_tx) / elapsed) : 0;
            uint64_t rx_speed = elapsed > 0 ? static_cast<uint64_t>((current_rx - last_rx) / elapsed) : 0;
            last_sample = sample;
            if (now_ms - last_ping_reply.load() > 3000) current_ping = -1;
            
            std::cout << "\r[STATS] Ping: " << current_ping << " ms | "
                      << "Tx: " << format_bytes(current_tx) << " (" << format_bits_per_sec(tx_speed) << ") | "
                      << "Errors Tx/Rx: " << tx_errors.load() << "/" << rx_errors.load()
                      << " Invalid Tx/Rx: " << tx_invalid.load() << "/" << invalid_packets.load()
                      << " LastWSA: " << last_send_error.load() << " | "
                      << "Rx: " << format_bytes(current_rx) << " (" << format_bits_per_sec(rx_speed) << ")          " 
                      << std::flush;
                      
            last_tx = current_tx;
            last_rx = current_rx;
        }
        
        // Sleep ~1 second
        WaitForSingleObject(stop_event, 1000);
    }
    if (enable_stats) std::cout << std::endl;
}

// Convert std::string to std::wstring for Wintun API
std::wstring s2ws(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

int main() {
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    cleanup_done = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop_event || !cleanup_done) return 1;
    SetConsoleCtrlHandler(ConsoleCleanupHandler, TRUE);

    try {
    char executable[MAX_PATH];
    DWORD path_length = GetModuleFileNameA(NULL, executable, MAX_PATH);
    if (!path_length || path_length >= MAX_PATH) throw std::runtime_error("Cannot resolve executable directory");
    std::string config_path(executable, path_length);
    config_path = config_path.substr(0, config_path.find_last_of("\\/" ) + 1) + "tunnel.conf";
    std::cout << "[INFO] Configuration: " << config_path << std::endl;
    auto config = parse_config(config_path);
    
    // Config defaults
    server_ip_str = config.count("SERVER_IP") ? config["SERVER_IP"] : "127.0.0.1";
    std::string server_port = config.count("SERVER_PORT") ? config["SERVER_PORT"] : "41195";
    tun_name_str = config.count("CLIENT_TUN_NAME") ? config["CLIENT_TUN_NAME"] : "GameTunnel";
    std::string tun_name = tun_name_str;
    std::string tun_ip = config.count("CLIENT_TUN_IP") ? config["CLIENT_TUN_IP"] : "10.9.0.2";
    std::string tun_mask = config.count("CLIENT_TUN_MASK") ? config["CLIENT_TUN_MASK"] : "255.255.255.0";
    std::string dns = config.count("CLIENT_DNS") ? config["CLIENT_DNS"] : "8.8.8.8";
    std::string gateway = config.count("CLIENT_GATEWAY") ? config["CLIENT_GATEWAY"] : "10.9.0.1";
    std::string secret = config.count("SECRET") ? config["SECRET"] : "RawTunV1";
    std::string mtu = config.count("MTU") ? config["MTU"] : "1400";
    bool enable_stats = (config.count("STATS") && config["STATS"] == "0") ? false : true;

    rawtun::number(server_port, 1, 65535);
    rawtun::number(mtu, 576, rawtun::max_ip_size);
    in_addr check = {};
    for (const auto& ip : {server_ip_str, tun_ip, tun_mask, dns, gateway})
        if (inet_pton(AF_INET, ip.c_str(), &check) != 1) throw std::runtime_error("Invalid IPv4 configuration");
    if (!rawtun::safe_name(tun_name)) throw std::runtime_error("Invalid adapter name");

    memcpy(auth_header, secret.data(), std::min(secret.size(), sizeof(auth_header)));

    if (!InitializeWintun()) {
        std::cerr << "[ERROR] Failed to load wintun.dll. Is it in the same directory?" << std::endl;
        CleanupTunnel();
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) { CleanupTunnel(); return 1; }

    std::cout << "[INFO] Creating Wintun adapter: " << tun_name << "..." << std::endl;
    adapter = WintunCreateAdapter(s2ws(tun_name).c_str(), L"Wintun", NULL);
    if (!adapter) {
        std::cerr << "[ERROR] Failed to create Wintun adapter. Run as Administrator!" << std::endl;
        CleanupTunnel();
        return 1;
    }

    std::cout << "[INFO] Assigning Virtual IP and MTU " << mtu << "..." << std::endl;
    std::string ip_cmd = "netsh interface ip set address name=\"" + tun_name + "\" static " + tun_ip + " " + tun_mask + " none";
    if (system(ip_cmd.c_str()) != 0) throw std::runtime_error("Interface configuration failed");
    
    std::string mtu_cmd = "netsh interface ipv4 set subinterface \"" + tun_name + "\" mtu=" + mtu + " store=persistent";
    if (system(mtu_cmd.c_str()) != 0) throw std::runtime_error("Interface configuration failed");

    std::cout << "[INFO] Assigning DNS Server: " << dns << "..." << std::endl;
    std::string dns_cmd = "netsh interface ip set dnsservers name=\"" + tun_name + "\" static " + dns + " validate=no";
    if (system(dns_cmd.c_str()) != 0) throw std::runtime_error("Interface configuration failed");
    
    // 1. Find the physical gateway and route the SERVER IP outside the VPN
    DWORD destIP;
    inet_pton(AF_INET, server_ip_str.c_str(), &destIP);
    MIB_IPFORWARDROW routeRow;
    if (GetBestRoute(destIP, 0, &routeRow) == NO_ERROR) {
        struct in_addr gw_addr;
        gw_addr.s_addr = routeRow.dwForwardNextHop;
        std::string orig_gw = inet_ntoa(gw_addr);
        if (orig_gw == "0.0.0.0") orig_gw = server_ip_str;

        std::string server_route = "route add " + server_ip_str + " mask 255.255.255.255 " + orig_gw + " IF " + std::to_string(routeRow.dwForwardIfIndex);
        std::cout << "[INFO] Bypassing tunnel for VPN Server IP..." << std::endl;
        if (system(server_route.c_str()) != 0) throw std::runtime_error("Server bypass route failed");
        server_route_added = true;
        server_route_delete = "route delete " + server_ip_str + " mask 255.255.255.255 " + orig_gw +
            " IF " + std::to_string(routeRow.dwForwardIfIndex) + " >nul 2>&1";
    } else throw std::runtime_error("Cannot find physical server route");

    // 2. Add two /1 routes to cleanly override the default 0.0.0.0/0 route
    std::cout << "[INFO] Overriding default routes to force traffic through tunnel..." << std::endl;
    std::string route1 = "netsh interface ipv4 add route 0.0.0.0/1 \"" + tun_name + "\" " + gateway + " store=active";
    std::string route2 = "netsh interface ipv4 add route 128.0.0.0/1 \"" + tun_name + "\" " + gateway + " store=active";
    if (system(route1.c_str()) != 0) throw std::runtime_error("First tunnel route failed");
    route1_added = true;
    if (system(route2.c_str()) != 0) throw std::runtime_error("Second tunnel route failed");
    route2_added = true;

    session = WintunStartSession(adapter, 0x400000);
    if (!session) { CleanupTunnel(); return 1; }

    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(std::stoi(server_port));
    inet_pton(AF_INET, server_ip_str.c_str(), &server_addr.sin_addr);

    DWORD receive_timeout = 100;
    if (udp_socket == INVALID_SOCKET ||
        connect(udp_socket, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR ||
        setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&receive_timeout), sizeof(receive_timeout)) == SOCKET_ERROR ||
        setsockopt(udp_socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&receive_timeout), sizeof(receive_timeout)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] UDP initialization failed: " << WSAGetLastError() << std::endl;
        CleanupTunnel();
        return 1;
    }

    std::cout << "[INFO] Tunnel is now active. Authenticating and forwarding packets to " << server_ip_str << ":" << server_port << "..." << std::endl;
    std::cout << "[INFO] Press ENTER to gracefully stop the tunnel." << std::endl;

    std::thread t1, t2, t3;
    try {
        t1 = std::thread(WintunToUdpThread, server_addr);
        t2 = std::thread(UdpToWintunThread);
        t3 = std::thread(KeepAliveThread, server_addr, enable_stats);
    } catch (...) {
        keepRunning = false;
        SetEvent(stop_event);
        if (t1.joinable()) t1.join();
        if (t2.joinable()) t2.join();
        if (t3.joinable()) t3.join();
        throw;
    }

    while (keepRunning) {
        if (_kbhit() && _getch() == '\r') break;
        WaitForSingleObject(stop_event, 50);
    }
    keepRunning = false;
    SetEvent(stop_event);

    if (t1.joinable()) t1.join();
    if (t2.joinable()) t2.join();
    if (t3.joinable()) t3.join();
    CleanupTunnel();

    std::cout << "[INFO] Tunnel successfully stopped. Network restored." << std::endl;
    SetEvent(cleanup_done);

    return 0;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        CleanupTunnel();
        SetEvent(cleanup_done);
        return 1;
    }
}