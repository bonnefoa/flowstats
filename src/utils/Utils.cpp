#include "Utils.hpp"
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <pdu.h>
#include <spdlog/spdlog.h>
#include <sys/socket.h>

namespace flowstats {

auto getTimevalDeltaMs(timeval start, timeval end) -> uint32_t
{
    return (end.tv_sec * 1000 + end.tv_usec / 1000) - (start.tv_sec * 1000 + start.tv_usec / 1000);
}

auto timevalInMs(timeval tv) -> uint32_t
{
    uint32_t ms = 1000 * tv.tv_sec + tv.tv_usec / 1000;
    return ms;
}

auto getTimevalDeltaS(timeval start, timeval end) -> uint32_t
{
    return end.tv_sec - start.tv_sec;
}

auto directionToString(enum Direction direction) -> std::string
{
    if (direction == FROM_CLIENT) {
        return "C->S";
    }
    return "S->C";
}

auto directionToString(uint8_t direction) -> std::string
{
    if (direction == FROM_CLIENT) {
        return "C->S";
    }
    return "S->C";
}

auto split(const std::string& s, char delimiter) -> std::vector<std::string>
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

auto splitSet(const std::string& s, char delimiter) -> std::set<std::string>
{
    std::set<std::string> res;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        res.insert(token);
    }
    return res;
}

template <std::size_t... Is>
auto fmtVector(const std::string& format,
    const std::vector<std::string>& v,
    std::index_sequence<Is...>) -> std::string
{
    return fmt::format(format, v[Is]...);
}

template <std::size_t N>
auto fmtVector(const std::string& format,
    const std::vector<std::string>& v) -> std::string
{
    return fmtVector(format, v, std::make_index_sequence<N>());
}

auto resolveDns(const std::string& domain) -> std::vector<std::string>
{
    struct addrinfo hints {
    }, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;
    std::vector<std::string> ips;

    int errcode = getaddrinfo(domain.c_str(), nullptr, &hints, &res);
    if (errcode != 0) {
        perror("getaddrinfo");
        return ips;
    }

    char ip[20];
    while (res) {
        void* ptr = &(reinterpret_cast<struct sockaddr_in*>(res->ai_addr))->sin_addr;
        inet_ntop(res->ai_family, ptr, ip, 20);
        ips.emplace_back(ip);
        spdlog::debug("Resolved {} -> {}", domain, ip);
        res = res->ai_next;
    }
    return ips;
}

static void resolveDomains(const std::vector<std::string>& initialDomains,
    std::map<uint32_t, std::string> ipToFqdn)
{
    for (const auto& domain : initialDomains) {
        std::vector<std::string> ips = resolveDns(domain);
        for (auto& ip : ips) {
            ipToFqdn[Tins::IPv4Address(ip)] = domain;
        }
    }
}

auto getIpToFqdn(const std::vector<std::string>& initialDomains) -> std::map<uint32_t, std::string>
{
    std::map<uint32_t, std::string> ipToFqdn;
    ipToFqdn[Tins::IPv4Address("127.0.0.1")] = "localhost";
    resolveDomains(initialDomains, ipToFqdn);
    return ipToFqdn;
}

auto stringsToInts(const std::vector<std::string>& strInts) -> std::set<int>
{
    std::set<int> res;
    for (const auto& strInt : strInts) {
        res.insert(atoi(strInt.c_str()));
    }
    return res;
}

auto getDomainToServerPort(const std::vector<std::string>& initialServerPorts) -> std::map<std::string, uint16_t>
{
    std::map<std::string, uint16_t> res;
    for (const auto& serviceToPort : initialServerPorts) {
        std::vector<std::string> pair = split(serviceToPort, ':');
        res[pair[0]] = std::stoi(pair[1]);
    }
    return res;
}

static auto prettyFormatGeneric(int num, std::vector<std::string> suffixes) -> std::string
{
    int unit = 0;
    double currentCount = num;
    while (currentCount >= 1000 && unit < suffixes.size()) {
        unit++;
        currentCount /= 1000;
    }
    if (currentCount - floor(currentCount) == 0.0) {
        return fmt::format("{}{}", static_cast<int>(currentCount), suffixes[unit]);
    } else {
        return fmt::format("{:.1f}{}", currentCount, suffixes[unit]);
    }
}

auto prettyFormatNumber(int num) -> std::string
{
    std::vector<std::string> suffixes = { "", "K" };
    return prettyFormatGeneric(num, suffixes);
}

auto prettyFormatMs(int ms) -> std::string
{
    std::vector<std::string> suffixes = { "ms", "s" };
    return prettyFormatGeneric(ms, suffixes);
}

auto prettyFormatBytes(int bytes) -> std::string
{
    std::vector<std::string> suffixes = { "B", "KB", "MB", "GB", "TB", "PB", "EB" };
    int unit = 0;
    double currentCount = bytes;
    while (currentCount >= 1024 && unit < suffixes.size()) {
        unit++;
        currentCount /= 1024;
    }
    if (currentCount - floor(currentCount) == 0.0) {
        return fmt::format("{} {}", static_cast<int>(currentCount), suffixes[unit]);
    } else {
        return fmt::format("{:.1f} {}", currentCount, suffixes[unit]);
    }
}

auto packetToTimeval(const Tins::Packet& packet) -> timeval
{
    auto ts = packet.timestamp();
    return { ts.seconds(), ts.microseconds() };
}

auto getFlowFqdn(FlowstatsConfiguration& conf, uint32_t srvIp) -> std::optional<std::string>
{
    std::optional<std::string> fqdn;
    const std::lock_guard<std::mutex> lock(conf.ipToFqdnMutex);
    auto it = conf.ipToFqdn.find(srvIp);
    if (it == conf.ipToFqdn.end()) {
        if (conf.displayUnknownFqdn == false) {
            return {};
        }
        fqdn = "Unknown";
        return fqdn;
    }
    fqdn = it->second;
    return fqdn;
}
} // namespace flowstats
