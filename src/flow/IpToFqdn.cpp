#include "IpToFqdn.hpp"
#include <arpa/inet.h>
#include <fmt/ostream.h>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace flowstats {

IpToFqdn::IpToFqdn(FlowstatsConfiguration const& flowstatsConfiguration,
    std::vector<std::string> const& initialDomains,
    std::string const& localhostIp)
    : conf(flowstatsConfiguration)
{
    std::map<uint32_t, std::string> ipToFqdn;
    ipToFqdn[Tins::IPv4Address("127.0.0.1")] = "localhost";
    if (!localhostIp.empty()) {
        ipToFqdn[Tins::IPv4Address(localhostIp)] = "localhost";
    }
    resolveDomains(initialDomains, ipToFqdn);
}

auto IpToFqdn::resolveDns(std::string const& domain) -> std::vector<std::string>
{
    struct addrinfo hints = {};
    struct addrinfo* res;
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
        SPDLOG_DEBUG("Resolved {} -> {}", domain, ip);
        res = res->ai_next;
    }
    return ips;
}

auto IpToFqdn::resolveDomains(const std::vector<std::string>& initialDomains,
    std::map<uint32_t, std::string> ipToFqdn) -> void
{
    for (const auto& domain : initialDomains) {
        std::vector<std::string> ips = resolveDns(domain);
        for (auto& ip : ips) {
            ipToFqdn[Tins::IPv4Address(ip)] = domain;
        }
    }
}

auto IpToFqdn::updateDnsCache() -> void
{
    for (auto const& i : ipToFqdn) {
        fmt::print(ipv4CacheFile, "{} {}",
            i.first,
            i.second);
    }
}

auto IpToFqdn::updateFqdn(std::string const& fqdn,
    std::vector<Tins::IPv4Address> const& ips,
    std::vector<Tins::IPv6Address> const& ipv6) -> void
{
    const std::lock_guard<std::mutex> lock(mutex);
    for (auto const& ip : ips) {
        SPDLOG_DEBUG("Fqdn mapping {} -> {}", ip.to_string(), fqdn);
        ipToFqdn[ip] = fqdn;
    }
    for (auto const& ip : ipv6) {
        SPDLOG_DEBUG("Fqdn mapping {} -> {}", ip.to_string(), fqdn);
        ipv6ToFqdn[ip] = fqdn;
    }
}

auto IpToFqdn::getFlowFqdn(IPAddress const& addr) -> std::optional<std::string>
{
    std::optional<std::string> fqdn = {};
    const std::lock_guard<std::mutex> lock(mutex);
    if (addr.getIsV6()) {
        auto it = ipv6ToFqdn.find(addr.getAddrV6());
        if (it != ipv6ToFqdn.end()) {
            fqdn = it->second;
        }
    } else {
        auto it = ipToFqdn.find(addr.getAddrV4());
        if (it != ipToFqdn.end()) {
            fqdn = it->second;
        }
    }
    if (fqdn->empty()) {
        if (conf.getDisplayUnknownFqdn() == false) {
            return {};
        }
        return "Unknown";
    }
    return fqdn;
}

} // namespace flowstats
