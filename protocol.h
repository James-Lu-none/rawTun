#pragma once
#include <cstddef>
#include <string>
#include <stdexcept>
#include <algorithm>

namespace rawtun {
constexpr unsigned header_size = 8;
constexpr unsigned max_ip_size = 65507 - header_size;
inline bool valid_ipv4(const char* data, std::size_t size) {
    if (size < 20 || size > max_ip_size) return false;
    auto ip = reinterpret_cast<const unsigned char*>(data);
    unsigned ihl = (ip[0] & 15) * 4;
    return (ip[0] >> 4) == 4 && ihl >= 20 && ihl <= size &&
           unsigned((ip[2] << 8) | ip[3]) == size;
}
inline unsigned number(const std::string& value, unsigned low, unsigned high) {
    if (value.empty() || value.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("Invalid numeric configuration");
    unsigned long n = std::stoul(value);
    if (n < low || n > high) throw std::runtime_error("Configuration out of range");
    return static_cast<unsigned>(n);
}
inline bool safe_name(const std::string& value) {
    return !value.empty() && value.find_first_not_of(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_- .") == std::string::npos;
}
}
