#include <iostream>
#include "protocol.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <map>
#include <fstream>
#include <string>
#include <cerrno>
#include <chrono>
#include <cstdint>

volatile sig_atomic_t keepRunning = 1;

void sig_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        keepRunning = false;
    }
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

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) return fd;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 

    if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

int main() {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    try {
    auto config = parse_config("tunnel.conf");
    
    std::string port_str = config.count("SERVER_PORT") ? config["SERVER_PORT"] : "41195";
    std::string tun_dev = config.count("SERVER_TUN_DEV") ? config["SERVER_TUN_DEV"] : "";
    std::string tun_ip = config.count("SERVER_TUN_IP") ? config["SERVER_TUN_IP"] : "10.9.0.1";
    std::string tun_mask = config.count("SERVER_TUN_MASK") ? config["SERVER_TUN_MASK"] : "24";
    std::string secret = config.count("SECRET") ? config["SECRET"] : "RawTunV1";
    std::string mtu = config.count("MTU") ? config["MTU"] : "1400";
    
    rawtun::number(port_str, 1, 65535);
    rawtun::number(mtu, 576, rawtun::max_ip_size);
    rawtun::number(tun_mask, 0, 32);
    in_addr check = {};
    if (inet_pton(AF_INET, tun_ip.c_str(), &check) != 1 ||
        (!tun_dev.empty() && (!rawtun::safe_name(tun_dev) || tun_dev.size() >= IFNAMSIZ || tun_dev.find(' ') != std::string::npos)))
        throw std::runtime_error("Invalid TUN configuration");
    char auth_header[8] = {0};
    memcpy(auth_header, secret.data(), std::min(secret.size(), sizeof(auth_header)));

    char tun_name[IFNAMSIZ] = {0};
    if (!tun_dev.empty()) {
        strncpy(tun_name, tun_dev.c_str(), IFNAMSIZ - 1);
    }
    
    int tun_fd = tun_alloc(tun_name);
    if (tun_fd < 0) {
        std::cerr << "[ERROR] Failed to allocate TUN device. Run as root." << std::endl;
        return 1;
    }

    std::cout << "[INFO] Allocated TUN device: " << tun_name << std::endl;

    std::string ip_cmd = "ip addr add " + tun_ip + "/" + tun_mask + " dev " + tun_name;
    std::string mtu_cmd = "ip link set dev " + std::string(tun_name) + " mtu " + mtu;
    std::string up_cmd = "ip link set dev " + std::string(tun_name) + " up";
    
    std::cout << "[INFO] Configuring IP and MTU " << mtu << "..." << std::endl;
    if (system(ip_cmd.c_str()) || system(mtu_cmd.c_str()) || system(up_cmd.c_str())) {
        std::cerr << "[ERROR] Interface configuration failed.\n";
        close(tun_fd);
        return 1;
    }

    int udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (udp_fd < 0 || fcntl(tun_fd, F_SETFL, O_NONBLOCK) < 0) {
        perror("socket/nonblocking");
        if (udp_fd >= 0) close(udp_fd);
        close(tun_fd);
        return 1;
    }
    struct sockaddr_in server_addr = {}, client_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(std::stoi(port_str));

    if (bind(udp_fd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[ERROR] Failed to bind to UDP port " << port_str << std::endl;
        close(udp_fd);
        close(tun_fd);
        return 1;
    }

    struct pollfd fds[2];
    fds[0].fd = tun_fd; fds[0].events = POLLIN;
    fds[1].fd = udp_fd; fds[1].events = POLLIN;

    // Reserve header space and read directly behind it: no payload copy on TX.
    char buffer[65535];
    memcpy(buffer, auth_header, 8);
    bool client_connected = false;
    uint64_t tx_errors = 0, rx_errors = 0, invalid = 0;
    uint64_t short_packets = 0, auth_failed = 0, bad_ipv4 = 0, ping_received = 0;
    auto next_stats = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    std::cout << "[INFO] Server active on UDP port " << port_str << std::endl;

    bool failed = false;
    while (keepRunning) {
        int ready = poll(fds, 2, 1000);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            failed = true;
            break;
        }
        if ((fds[0].revents | fds[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) {
            std::cerr << "[ERROR] Tunnel/socket poll failure.\n";
            failed = true;
            break;
        }
        // Bound each drain so neither direction can starve the other.
        if (fds[1].revents & POLLIN) {
            for (int i = 0; i < 32 && keepRunning; ++i) {
                sockaddr_in sender = {};
                socklen_t sender_len = sizeof(sender);
                ssize_t n = recvfrom(udp_fd, buffer, sizeof(buffer), 0,
                                     reinterpret_cast<sockaddr*>(&sender), &sender_len);
                if (n < 0) {
                    if (errno == EINTR) { --i; continue; }
                    if (errno != EAGAIN && errno != EWOULDBLOCK) ++rx_errors;
                    break;
                }
                if (n < 8) { ++invalid; ++short_packets; continue; }
                if (memcmp(buffer, auth_header, 8) != 0) {
                    ++invalid;
                    if (++auth_failed == 1) {
                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &sender.sin_addr, ip, sizeof(ip));
                        std::cerr << "[WARN] Header mismatch from " << ip << ":" << ntohs(sender.sin_port)
                                  << "; check both SECRET settings and loaded config paths.\n";
                    }
                    continue;
                }
                // Legacy keepalive is exactly 8-byte header + 8-byte timestamp.
                if (n != 16) {
                    if (!rawtun::valid_ipv4(buffer + 8, n - 8)) { ++invalid; ++bad_ipv4; continue; }
                }
                // Never change the active peer before validating the datagram.
                client_addr = sender;
                client_connected = true;
                if (n == 16) {
                    ++ping_received;
                    if (sendto(udp_fd, buffer, n, 0, reinterpret_cast<sockaddr*>(&sender), sender_len) != n)
                        ++tx_errors;
                } else if (write(tun_fd, buffer + 8, n - 8) != n - 8) ++rx_errors;
            }
        }
        if (fds[0].revents & POLLIN) {
            memcpy(buffer, auth_header, 8);
            for (int i = 0; i < 32 && keepRunning; ++i) {
                ssize_t n = read(tun_fd, buffer + 8, sizeof(buffer) - 8);
                if (n < 0) {
                    if (errno == EINTR) { --i; continue; }
                    if (errno != EAGAIN && errno != EWOULDBLOCK) ++tx_errors;
                    break;
                }
                if (n == 0) break;
                if (client_connected && sendto(udp_fd, buffer, n + 8, 0,
                    reinterpret_cast<sockaddr*>(&client_addr), sizeof(client_addr)) != n + 8) ++tx_errors;
            }
        }
        auto now = std::chrono::steady_clock::now();
        if (now >= next_stats) {
            if (tx_errors || rx_errors || invalid)
                std::cout << "[STATS] cumulative tx_errors=" << tx_errors
                          << " rx_errors=" << rx_errors << " invalid=" << invalid
                          << " short=" << short_packets << " auth_failed=" << auth_failed
                          << " bad_ipv4=" << bad_ipv4 << " ping_received=" << ping_received << std::endl;
            next_stats = now + std::chrono::seconds(10);
        }
    }

    close(tun_fd);
    close(udp_fd);
    std::cout << "\n[INFO] Server shut down gracefully." << std::endl;
    return failed ? 1 : 0;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }
}