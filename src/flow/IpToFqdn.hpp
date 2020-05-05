#pragma once

#include "Configuration.hpp"
#include <cstdint> // for uint16_t, uint32_t
#include <map> // for map
#include <mutex> // for mutex
#include <string> // for string, allocator
#include <tins/ip_address.h>
#include <vector>

namespace flowstats {

class IpToFqdn {
public:
    IpToFqdn(FlowstatsConfiguration const& flowstatsConfiguration)
        : conf(flowstatsConfiguration) {};
    IpToFqdn(FlowstatsConfiguration const& flowstatsConfiguration,
        std::vector<std::string> const& initialDomains,
        std::string localhostIp);
    virtual ~IpToFqdn() = default;

    [[nodiscard]] auto getIpToFqdn() const -> std::map<uint32_t, std::string> const& { return ipToFqdn; };
    [[nodiscard]] auto getIpToFqdn() -> std::map<uint32_t, std::string> { return ipToFqdn; };

    auto getFlowFqdn(uint32_t srvIp) -> std::optional<std::string>;
    auto updateFqdn(std::string fqdn,
        Tins::IPv4Address const& ip) -> void;
    auto updateFqdn(std::string fqdn,
        std::vector<Tins::IPv4Address> const& ips) -> void;

private:
    FlowstatsConfiguration const& conf;

    std::mutex mutex;
    std::map<uint32_t, std::string> ipToFqdn;

    auto setIpToFqdn(std::map<uint32_t, std::string> i) { ipToFqdn = std::move(i); };
    auto resolveDomains(const std::vector<std::string>& initialDomains,
        std::map<uint32_t, std::string> ipToFqdn) -> void;
    auto resolveDns(std::string const& domain) -> std::vector<std::string>;
};

} // namespace flowstats
