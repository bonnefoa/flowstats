#pragma once

#include "AggregatedFlow.hpp"
#include "Field.hpp"
#include "Flow.hpp"
#include "Stats.hpp"
#include <tins/dns.h>

namespace flowstats {

class AggregatedTcpKey : public AggregatedKey {
public:
    AggregatedTcpKey(std::string const& fqdn, IPv4 ip, Port port)
        : AggregatedKey(fqdn)
        , ip(ip)
        , port(port) {};

    auto operator<(AggregatedTcpKey const& b) const -> bool
    {
        auto leftFqdn = getFqdn();
        auto rightFqdn = b.getFqdn();
        return std::tie(leftFqdn, ip, port) < std::tie(rightFqdn,
                   b.ip, b.port);
    }

    [[nodiscard]] auto toString() const -> std::string
    {
        return fmt::format("{} {}:{}", getFqdn(), ip, port);
    };

private:
    IPv4 ip;
    Port port;
};

struct AggregatedDnsKey : AggregatedKey {
    AggregatedDnsKey(std::string const& fqdn, Tins::DNS::QueryType dnsType,
        Transport transport)
        : AggregatedKey(fqdn)
        , dnsType(dnsType)
        , transport(transport) {};

    auto operator<(AggregatedDnsKey const& b) const -> bool
    {
        auto leftFqdn = getFqdn();
        auto rightFqdn = b.getFqdn();
        return std::tie(leftFqdn, dnsType, transport) < std::tie(rightFqdn,
                   b.dnsType, b.transport);
    }

private:
    Tins::DNS::QueryType dnsType;
    Transport transport;
};
} // namespace flowstats
