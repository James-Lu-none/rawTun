#include <iostream>
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

volatile bool keepRunning = true;

void sig_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        keepRunning = false;
    }
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

    auto config = parse_config("tunnel.conf");
    
    std::string port_str = config.count("SERVER_PORT") ? config["SERVER_PORT"] : "41195";
    std::string tun_dev = config.count("SERVER_TUN_DEV") ? config["SERVER_TUN_DEV"] : "";
    std::string tun_ip = config.count("SERVER_TUN_IP") ? config["SERVER_TUN_IP"] : "10.9.0.1";
    std::string tun_mask = config.count("SERVER_TUN_MASK") ? config["SERVER_TUN_MASK"] : "24";
    std::string secret = config.count("SECRET") ? config["SECRET"] : "RawTunV1";
    std::string mtu = config.count("MTU") ? config["MTU"] : "1400";
    
    char auth_header[8] = {0};
    strncpy(auth_header, secret.c_str(), 8);

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
    if(system(ip_cmd.c_str())) {}
    if(system(mtu_cmd.c_str())) {}
    if(system(up_cmd.c_str())) {}

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server_addr = {}, client_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(std::stoi(port_str));

    if (bind(udp_fd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[ERROR] Failed to bind to UDP port " << port_str << std::endl;
        return 1;
    }

    struct pollfd fds[2];
    fds[0].fd = tun_fd; fds[0].events = POLLIN;
    fds[1].fd = udp_fd; fds[1].events = POLLIN;

    char buffer[65535];
    char send_buffer[65535];
    socklen_t client_len = sizeof(client_addr);
    bool client_connected = false;

    std::cout << "[INFO] Server active on UDP port " << port_str << " with auth check. Awaiting packets..." << std::endl;

    while (keepRunning) {
        if (poll(fds, 2, 1000) < 0) break;

        if (fds[0].revents & POLLIN) {
            int nread = read(tun_fd, buffer, sizeof(buffer));
            if (nread > 0 && client_connected) {
                // Prepend auth header
                memcpy(send_buffer, auth_header, 8);
                memcpy(send_buffer + 8, buffer, nread);
                sendto(udp_fd, send_buffer, nread + 8, 0, (struct sockaddr *)&client_addr, client_len);
            }
        }

        if (fds[1].revents & POLLIN) {
            int nread = recvfrom(udp_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_len);
            if (nread >= 8) {
                if (memcmp(buffer, auth_header, 8) == 0) {
                    if (!client_connected) {
                        char client_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
                        std::cout << "[INFO] Authenticated packet received. Client locked to " 
                                  << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;
                    }
                    client_connected = true;
                    
                    if (nread == 16) {
                        // Echo ping packet back to client
                        sendto(udp_fd, buffer, 16, 0, (struct sockaddr *)&client_addr, client_len);
                    } else if (nread > 8) {
                        // It's a real IP packet, strip header and inject
                        if(write(tun_fd, buffer + 8, nread - 8)) {}
                    }
                }
            }
        }
    }

    close(tun_fd);
    close(udp_fd);
    std::cout << "\n[INFO] Server shut down gracefully." << std::endl;
    return 0;
}