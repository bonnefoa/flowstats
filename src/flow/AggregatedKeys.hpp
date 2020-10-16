#pragma once

#include "Field.hpp"
#include "Flow.hpp"
#include "Stats.hpp"
#include <tins/dns.h>

namespace flowstats {

class AggregatedKey {
public:
    AggregatedKey(std::string const& fqdn,
        IPAddress const& address,
        Port port,
        Tins::DNS::QueryType dnsType = Tins::DNS::A,
        Transport transport = Transport::TCP)
        : fqdn(fqdn)
        , address(address)
        , port(port)
        , dnsType(dnsType)
        , transport(transport) {};

    static auto aggregatedIpTcpKey(std::string const& fqdn,
        IPAddress const& address,
        Port port)
    {
        return AggregatedKey(fqdn, address, port);
    }

    static auto aggregatedDnsKey(std::string const& fqdn,
        Tins::DNS::QueryType dnsType,
        Transport transport)
    {
        return AggregatedKey(fqdn, {}, 0, dnsType, transport);
    }

    virtual ~AggregatedKey() = default;

    auto operator<(AggregatedKey const& b) const -> bool
    {
        return fqdn < b.fqdn
            && address < b.address
            && port < b.port
            && dnsType < b.dnsType
            && transport < b.transport;
    }

    auto operator==(AggregatedKey const& b) const -> bool
    {
        return fqdn == b.fqdn
            && address == b.address
            && port == b.port
            && dnsType == b.dnsType
            && transport == b.transport;
    }

    [[nodiscard]] auto hash() const
    {
        return std::hash<std::string>()(fqdn)
            + std::hash<IPAddress>()(address)
            + std::hash<uint16_t>()(port)
            + std::hash<uint16_t>()(dnsType)
            + std::hash<uint16_t>()(transport);
    };

private:
    std::string fqdn;
    IPAddress address;
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
