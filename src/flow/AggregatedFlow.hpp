#pragma once

#include "Flow.hpp"
#include "Utils.hpp"
#include <fmt/format.h>
#include <map>

namespace flowstats {

class AggregatedKey {
public:
    explicit AggregatedKey(std::string fqdn)
        : fqdn(std::move(fqdn)) {};
    virtual ~AggregatedKey() = default;
    auto operator<(AggregatedKey const& b) const -> bool
    {
        return fqdn < b.fqdn;
    }

    [[nodiscard]] auto getFqdn() const { return fqdn; }

private:
    friend class AggregatedTcpKey;
    std::string fqdn;
};

using AggregatedPairPointer = std::pair<AggregatedKey, Flow*>;

auto sortAggregatedPairByPacket(AggregatedPairPointer const& left,
    const AggregatedPairPointer& right) -> bool;
auto sortAggregatedPairByFqdn(AggregatedPairPointer const& left,
    const AggregatedPairPointer& right) -> bool;
auto sortAggregatedPairByByte(AggregatedPairPointer const& left,
    const AggregatedPairPointer& right) -> bool;

class AggregatedTcpKey : AggregatedKey {
public:
    AggregatedTcpKey(std::string const& fqdn, IPv4 ip, Port port)
        : AggregatedKey(fqdn)
        , ip(ip)
        , port(port) {};

    auto operator<(AggregatedTcpKey const& b) const -> bool
    {
        return std::tie(fqdn, ip, port) < std::tie(b.fqdn, b.ip, b.port);
    }

    [[nodiscard]] auto toString() const -> std::string
    {
        return fmt::format("{} {}:{}", fqdn, ip, port);
    };

private:
    IPv4 ip;
    Port port;
};
} // namespace flowstats
