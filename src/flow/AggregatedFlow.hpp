#pragma once

#include "Flow.hpp"
#include "Utils.hpp"
#include <fmt/format.h>
#include <map>

namespace flowstats {

template <class T>
struct ptr_less {
    bool operator()(T* lhs, T* rhs)
    {
        return *lhs < *rhs;
    }
};

class AggregatedKey {
public:
    AggregatedKey(std::string _fqdn)
        : fqdn(_fqdn) {};
    virtual ~AggregatedKey() {};
    bool operator<(AggregatedKey const& b) const
    {
        return fqdn < b.fqdn;
    }

protected:
    std::string fqdn;
};

using AggregatedPairPointer = std::pair<AggregatedKey, Flow*>;

bool sortAggregatedPairByPacket(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right);
bool sortAggregatedPairByFqdn(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right);
bool sortAggregatedPairByByte(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right);

struct AggregatedTcpKey : AggregatedKey {
    AggregatedTcpKey(std::string fqdn, IPv4 ip, Port port)
        : AggregatedKey(fqdn)
        , ip(ip)
        , port(port) {};

    bool operator<(AggregatedTcpKey const& b) const
    {
        return std::tie(fqdn, ip, port) < std::tie(b.fqdn, b.ip, b.port);
    }

    std::string toString()
    {
        return fmt::format("{} {}:{}", fqdn, ip, port);
    };

private:
    IPv4 ip;
    Port port;
};
}
