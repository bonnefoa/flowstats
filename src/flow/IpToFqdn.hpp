#pragma once

#include "Configuration.hpp"
#include <cstdint> // for uint16_t, uint32_t
#include <map> // for map
#include <mutex> // for mutex
#include <string> // for string, allocator
#include <tins/ip_address.h>
#include <tins/ipv6_address.h>
#include <vector>

namespace flowstats {

class IpToFqdn {
public:
    explicit IpToFqdn(FlowstatsConfiguration const& flowstatsConfiguration)
        : conf(flowstatsConfiguration) {};
    IpToFqdn(FlowstatsConfiguration const& flowstatsConfiguration,
        std::vector<std::string> const& initialDomains,
        std::string const& localhostIp);
    virtual ~IpToFqdn() = default;

    [[nodiscard]] auto getIpToFqdn() const -> std::map<uint32_t, std::string> const& { return ipToFqdn; };
    [[nodiscard]] auto getIpToFqdn() -> std::map<uint32_t, std::string> { return ipToFqdn; };

    auto getFlowFqdn(uint32_t srvIp) -> std::optional<std::string>;
    auto getFlowFqdn(Tins::IPv6Address ipv6) -> std::optional<std::string>;
    auto updateFqdn(std::string fqdn,
        std::vector<Tins::IPv4Address> const& ips,
        std::vector<Tins::IPv6Address> const& ipv6) -> void;

private:
    FlowstatsConfiguration const& conf;

    std::mutex mutex;
    std::map<uint32_t, std::string> ipToFqdn;
    std::map<Tins::IPv6Address, std::string> ipv6ToFqdn;

    auto resolveDomains(const std::vector<std::string>& initialDomains,
        std::map<uint32_t, std::string> ipToFqdn) -> void;
    auto resolveDns(std::string const& domain) -> std::vector<std::string>;
};

} // namespace flowstats
