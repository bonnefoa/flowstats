#pragma once

#include "Configuration.hpp"
#include "IPAddress.hpp"
#include <cstdint> // for uint16_t, uint32_t
#include <fstream>
#include <map> // for map
#include <mutex> // for mutex
#include <string> // for string, allocator
#include <tins/ip_address.h>
#include <tins/ipv6_address.h>
#include <vector>

namespace flowstats {

class IpToFqdn {
public:
    explicit IpToFqdn(FlowstatsConfiguration const& flowstatsConfiguration,
        std::vector<std::string> const& initialDomains = {},
        std::string const& localhostIp = "");
    virtual ~IpToFqdn() = default;

    auto getFlowFqdn(IPAddress const& addr) -> std::optional<std::string>;
    auto updateFqdn(std::string const& fqdn,
        std::vector<Tins::IPv4Address> const& ips,
        std::vector<Tins::IPv6Address> const& ipv6) -> void;

private:
    FlowstatsConfiguration const& conf;

    std::mutex mutex;
    std::map<Tins::IPv4Address, std::string> ipToFqdn;
    std::map<Tins::IPv6Address, std::string> ipv6ToFqdn;
    std::ofstream ipv4CacheFile;
    std::ofstream ipv6CacheFile;

    auto updateDnsCache() -> void;
    auto resolveDomains(const std::vector<std::string>& initialDomains,
        std::map<uint32_t, std::string> ipToFqdn) -> void;
    auto resolveDns(std::string const& domain) -> std::vector<std::string>;
};

} // namespace flowstats
