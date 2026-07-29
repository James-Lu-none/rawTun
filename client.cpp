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

// You must download wintun.h from the official Wintun repository and include it in your project folder
#include "wintun.h" 

#pragma comment(lib, "ws2_32.lib")

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
    while (keepRunning) {
        DWORD packetSize;
        BYTE* packet = WintunReceivePacket(session, &packetSize);
        if (packet) {
            sendto(udp_socket, (const char*)packet, packetSize, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
            WintunReleaseReceivePacket(session, packet);
        }
    }
}

void UdpToWintunThread() {
    char buffer[65535];
    while (keepRunning) {
        int nread = recvfrom(udp_socket, buffer, sizeof(buffer), 0, NULL, NULL);
        if (nread > 0) {
            BYTE* packet = WintunAllocateSendPacket(session, nread);
            if (packet) {
                memcpy(packet, buffer, nread);
                WintunSendPacket(session, packet);
            }
        }
    }
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

    auto config = parse_config("client.conf");
    
    // Config defaults
    std::string server_ip_str = config.count("SERVER_IP") ? config["SERVER_IP"] : "127.0.0.1";
    std::string server_port = config.count("SERVER_PORT") ? config["SERVER_PORT"] : "41195";
    std::string tun_name = config.count("TUN_NAME") ? config["TUN_NAME"] : "GameTunnel";
    std::string tun_ip = config.count("TUN_IP") ? config["TUN_IP"] : "10.9.0.2";
    std::string tun_mask = config.count("TUN_MASK") ? config["TUN_MASK"] : "255.255.255.0";
    std::string dns = config.count("DNS") ? config["DNS"] : "8.8.8.8";
    std::string gateway = config.count("GATEWAY") ? config["GATEWAY"] : "10.9.0.1";

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

    std::cout << "[INFO] Assigning Virtual IP: " << tun_ip << "..." << std::endl;
    std::string ip_cmd = "netsh interface ip set address name=\"" + tun_name + "\" static " + tun_ip + " " + tun_mask + " none";
    system(ip_cmd.c_str());
    
    std::cout << "[INFO] Assigning DNS Server: " << dns << "..." << std::endl;
    std::string dns_cmd = "netsh interface ip set dnsservers name=\"" + tun_name + "\" static " + dns + " validate=no";
    system(dns_cmd.c_str());
    
    std::string route_cmd = "route add 0.0.0.0 mask 0.0.0.0 " + gateway + " metric 1";
    system(route_cmd.c_str());

    session = WintunStartSession(adapter, 0x400000);

    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(std::stoi(server_port));
    inet_pton(AF_INET, server_ip_str.c_str(), &server_addr.sin_addr);

    std::cout << "[INFO] Tunnel Active! Forwarding packets to " << server_ip_str << ":" << server_port << "..." << std::endl;

    std::thread t1(WintunToUdpThread, server_addr);
    std::thread t2(UdpToWintunThread);

    t1.join();
    t2.join();

    return 0;
}