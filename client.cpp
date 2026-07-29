#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <fstream>
#include <string>
#include <map>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iphlpapi.h>

// You must download wintun.h from the official Wintun repository and include it in your project folder
#include "wintun.h" 

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Dynamic Wintun API Pointers
static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter;
static WINTUN_START_SESSION_FUNC* WintunStartSession;
static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC* WintunSendPacket;
static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter;

std::atomic<bool> keepRunning(true);
WINTUN_ADAPTER_HANDLE adapter = NULL;
WINTUN_SESSION_HANDLE session = NULL;
SOCKET udp_socket = INVALID_SOCKET;
char auth_header[8] = {0};
std::string server_ip_str;
std::string tun_name_str;

std::atomic<uint64_t> tx_bytes(0);
std::atomic<uint64_t> rx_bytes(0);
std::atomic<int> current_ping(0);

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

std::map<std::string, std::string> parse_config(const std::string& filename) {
    std::map<std::string, std::string> config;
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line)) {
        size_t comment = line.find('#');
        if (comment != std::string::npos) line = line.substr(0, comment);
        size_t eq = line.find('=');
        if (eq != std::string::npos) {
            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            if (!val.empty()) {
                val.erase(0, val.find_first_not_of(" \t"));
                val.erase(val.find_last_not_of(" \t") + 1);
            }
            config[key] = val;
        }
    }
    return config;
}

// Graceful cleanup on Ctrl+C or terminal close
BOOL WINAPI ConsoleCleanupHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        std::cout << "\n[INFO] Shutting down... Restoring network routes." << std::endl;
        keepRunning = false;
        
        if (session) {
            // EndSession function pointer omitted for brevity, usually required in full API
        }
        if (adapter) WintunCloseAdapter(adapter);
        if (udp_socket != INVALID_SOCKET) closesocket(udp_socket);
        
        // Remove VPN routes
        if (!tun_name_str.empty()) {
            system(("netsh interface ipv4 delete route 0.0.0.0/1 \"" + tun_name_str + "\"").c_str());
            system(("netsh interface ipv4 delete route 128.0.0.0/1 \"" + tun_name_str + "\"").c_str());
        }
        if (!server_ip_str.empty()) {
            std::string del_server = "route delete " + server_ip_str + " mask 255.255.255.255";
            system(del_server.c_str());
        }

        WSACleanup();
        
        // Exiting causes Wintun driver to delete the interface, auto-reverting standard routes
        ExitProcess(0);
        return TRUE;
    }
    return FALSE;
}

bool InitializeWintun() {
    HMODULE wintun = LoadLibraryA("wintun.dll");
    if (!wintun) return false;
    
    WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC*)GetProcAddress(wintun, "WintunCreateAdapter");
    WintunStartSession = (WINTUN_START_SESSION_FUNC*)GetProcAddress(wintun, "WintunStartSession");
    WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC*)GetProcAddress(wintun, "WintunReceivePacket");
    WintunReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC*)GetProcAddress(wintun, "WintunReleaseReceivePacket");
    WintunAllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC*)GetProcAddress(wintun, "WintunAllocateSendPacket");
    WintunSendPacket = (WINTUN_SEND_PACKET_FUNC*)GetProcAddress(wintun, "WintunSendPacket");
    WintunCloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC*)GetProcAddress(wintun, "WintunCloseAdapter");
    return true;
}

void WintunToUdpThread(sockaddr_in server_addr) {
    char send_buffer[65535];
    while (keepRunning) {
        DWORD packetSize;
        BYTE* packet = WintunReceivePacket(session, &packetSize);
        if (packet) {
            memcpy(send_buffer, auth_header, 8);
            memcpy(send_buffer + 8, packet, packetSize);
            sendto(udp_socket, send_buffer, packetSize + 8, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
            tx_bytes += packetSize;
            WintunReleaseReceivePacket(session, packet);
        }
    }
}

void UdpToWintunThread() {
    char buffer[65535];
    while (keepRunning) {
        int nread = recvfrom(udp_socket, buffer, sizeof(buffer), 0, NULL, NULL);
        if (nread >= 8) {
            if (memcmp(buffer, auth_header, 8) == 0) {
                if (nread == 16) {
                    // Ping echo received
                    int64_t sent_time;
                    memcpy(&sent_time, buffer + 8, 8);
                    auto now = std::chrono::steady_clock::now().time_since_epoch();
                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
                    current_ping = static_cast<int>(now_ms - sent_time);
                } else if (nread > 8) {
                    BYTE* packet = WintunAllocateSendPacket(session, nread - 8);
                    if (packet) {
                        memcpy(packet, buffer + 8, nread - 8);
                        WintunSendPacket(session, packet);
                        rx_bytes += (nread - 8);
                    }
                }
            }
        }
    }
}

void KeepAliveThread(sockaddr_in server_addr, bool enable_stats) {
    char ping_packet[16];
    memcpy(ping_packet, auth_header, 8);
    
    uint64_t last_tx = 0;
    uint64_t last_rx = 0;

    while (keepRunning) {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        int64_t timestamp = now_ms;
        memcpy(ping_packet + 8, &timestamp, 8);
        
        sendto(udp_socket, ping_packet, 16, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
        
        if (enable_stats) {
            uint64_t current_tx = tx_bytes.load();
            uint64_t current_rx = rx_bytes.load();
            uint64_t tx_speed = current_tx - last_tx;
            uint64_t rx_speed = current_rx - last_rx;
            
            std::cout << "\r[STATS] Ping: " << current_ping << " ms | "
                      << "Tx: " << format_bytes(current_tx) << " (" << format_bytes(tx_speed) << "/s) | "
                      << "Rx: " << format_bytes(current_rx) << " (" << format_bytes(rx_speed) << "/s)          " 
                      << std::flush;
                      
            last_tx = current_tx;
            last_rx = current_rx;
        }
        
        // Sleep ~1 second
        for(int i=0; i<10 && keepRunning; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
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
    SetConsoleCtrlHandler(ConsoleCleanupHandler, TRUE);

    auto config = parse_config("tunnel.conf");
    
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

    strncpy(auth_header, secret.c_str(), 8);

    if (!InitializeWintun()) {
        std::cerr << "[ERROR] Failed to load wintun.dll. Is it in the same directory?" << std::endl;
        return 1;
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    std::cout << "[INFO] Creating Wintun adapter: " << tun_name << "..." << std::endl;
    adapter = WintunCreateAdapter(s2ws(tun_name).c_str(), L"Wintun", NULL);
    if (!adapter) {
        std::cerr << "[ERROR] Failed to create Wintun adapter. Run as Administrator!" << std::endl;
        return 1;
    }

    std::cout << "[INFO] Assigning Virtual IP and MTU " << mtu << "..." << std::endl;
    std::string ip_cmd = "netsh interface ip set address name=\"" + tun_name + "\" static " + tun_ip + " " + tun_mask + " none";
    system(ip_cmd.c_str());
    
    std::string mtu_cmd = "netsh interface ipv4 set subinterface \"" + tun_name + "\" mtu=" + mtu + " store=persistent";
    system(mtu_cmd.c_str());

    std::cout << "[INFO] Assigning DNS Server: " << dns << "..." << std::endl;
    std::string dns_cmd = "netsh interface ip set dnsservers name=\"" + tun_name + "\" static " + dns + " validate=no";
    system(dns_cmd.c_str());
    
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
        system(server_route.c_str());
    }

    // 2. Add two /1 routes to cleanly override the default 0.0.0.0/0 route
    std::cout << "[INFO] Overriding default routes to force traffic through tunnel..." << std::endl;
    std::string route1 = "netsh interface ipv4 add route 0.0.0.0/1 \"" + tun_name + "\" " + gateway + " store=active";
    std::string route2 = "netsh interface ipv4 add route 128.0.0.0/1 \"" + tun_name + "\" " + gateway + " store=active";
    system(route1.c_str());
    system(route2.c_str());

    session = WintunStartSession(adapter, 0x400000);

    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(std::stoi(server_port));
    inet_pton(AF_INET, server_ip_str.c_str(), &server_addr.sin_addr);

    std::cout << "[INFO] Tunnel Active! Authenticating and forwarding packets to " << server_ip_str << ":" << server_port << "..." << std::endl;

    std::thread t1(WintunToUdpThread, server_addr);
    std::thread t2(UdpToWintunThread);
    std::thread t3(KeepAliveThread, server_addr, enable_stats);

    t1.join();
    t2.join();
    t3.join();

    return 0;
}