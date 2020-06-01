#pragma once

#include "Field.hpp"
#include "Flow.hpp"
#include "Stats.hpp"
#include <tins/dns.h>

namespace flowstats {

class AggregatedKey {
public:
    AggregatedKey(std::string const& fqdn,
        IPv4 ip,
        IPv6 ipv6,
        Port port,
        Tins::DNS::QueryType dnsType = Tins::DNS::A,
        Transport transport = Transport::TCP)
        : fqdn(fqdn)
        , ip(ip)
        , ipv6(ipv6)
        , port(port)
        , dnsType(dnsType)
        , transport(transport) {};

    static auto aggregatedIpv4TcpKey(std::string const& fqdn,
        IPv4 ip,
        Port port)
    {
        return AggregatedKey(fqdn, ip, {}, port);
    }

    static auto aggregatedIpv6TcpKey(std::string const& fqdn,
        IPv6 ipv6,
        Port port)
    {
        return AggregatedKey(fqdn, 0, ipv6, port);
    }

    static auto aggregatedDnsKey(std::string const& fqdn,
        Tins::DNS::QueryType dnsType,
        Transport transport)
    {
        return AggregatedKey(fqdn, 0, {}, 0, dnsType, transport);
    }

    virtual ~AggregatedKey() = default;

    auto operator<(AggregatedKey const& b) const -> bool
    {
        return fqdn < b.fqdn
            && ip < b.ip
            && ipv6 < b.ipv6
            && port < b.port
            && dnsType < b.dnsType
            && transport < b.transport;
    }

    auto operator==(AggregatedKey const& b) const -> bool
    {
        return fqdn == b.fqdn
            && ip == b.ip
            && ipv6 == b.ipv6
            && port == b.port
            && dnsType == b.dnsType
            && transport == b.transport;
    }

    [[nodiscard]] auto hash() const
    {
        return std::hash<std::string>()(fqdn)
            + std::hash<flowstats::IPv4>()(ip)
            + std::hash<flowstats::IPv6>()(ipv6)
            + std::hash<uint16_t>()(port)
            + std::hash<uint16_t>()(dnsType)
            + std::hash<uint16_t>()(transport);
    };

private:
    std::string fqdn;
    IPv4 ip;
    IPv6 ipv6;
    Port port;
    Tins::DNS::QueryType dnsType;
    Transport transport;
};

} // namespace flowstats

namespace std {

template <>
struct hash<flowstats::AggregatedKey> {
    auto operator()(const flowstats::AggregatedKey& key) const -> size_t
    {
        return key.hash();
    }
};

} // namespace std
