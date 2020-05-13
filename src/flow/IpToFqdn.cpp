#include "IpToFqdn.hpp"
#include <arpa/inet.h>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <spdlog/spdlog.h>
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
    struct addrinfo hints, *res;
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

auto IpToFqdn::updateFqdn(std::string fqdn,
    Tins::IPv4Address const& ip) -> void
{
    const std::lock_guard<std::mutex> lock(mutex);
    spdlog::debug("Fqdn mapping {} -> {}", ip.to_string(), fqdn);
    ipToFqdn[ip] = fqdn;
}

auto IpToFqdn::updateFqdn(std::string fqdn,
    std::vector<Tins::IPv4Address> const& ips) -> void
{
    const std::lock_guard<std::mutex> lock(mutex);
    for (auto const& ip : ips) {
        spdlog::debug("Fqdn mapping {} -> {}", ip.to_string(), fqdn);
        ipToFqdn[ip] = fqdn;
    }
}

auto IpToFqdn::getFlowFqdn(uint32_t srvIp) -> std::optional<std::string>
{
    std::optional<std::string> fqdn;
    const std::lock_guard<std::mutex> lock(mutex);
    auto it = ipToFqdn.find(srvIp);
    if (it == ipToFqdn.end()) {
        if (conf.getDisplayUnknownFqdn() == false) {
            return {};
        }
        fqdn = "Unknown";
        return fqdn;
    }
    fqdn = it->second;
    return fqdn;
}

} // namespace flowstats
