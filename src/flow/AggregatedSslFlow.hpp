#pragma once

#include "Flow.hpp"
#include "Stats.hpp"
#include "SslProto.hpp"

namespace flowstats {

class AggregatedSslFlow : public Flow {
public:
    AggregatedSslFlow()
        : Flow("Total"), tlsVersion(TLSVersion::UNKNOWN) {};

    AggregatedSslFlow(FlowId const& flowId, std::string const& fqdn)
        : Flow(flowId, fqdn), tlsVersion(TLSVersion::UNKNOWN) {};

    auto getFieldStr(Field field, Direction direction, int duration) const -> std::string override;
    auto resetFlow(bool resetTotal) -> void override;
    auto setTlsVersion(TLSVersion tlsVers) -> void;
    auto setDomain(std::string _domain) -> void { domain = std::move(_domain); }
    auto setSslCipherSuite(SSLCipherSuite _sslCipherSuite) -> void { sslCipherSuite = _sslCipherSuite; }
    auto addConnection(int delta) -> void;
    auto merge() -> void { connections.merge(); };

    [[nodiscard]] auto getDomain() const { return domain; }

    [[nodiscard]] static auto sortByConnections(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = static_cast<AggregatedSslFlow const*>(b);
        return aCast->totalConnections < bCast->totalConnections;
    }

    [[nodiscard]] static auto sortByConnectionRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = static_cast<AggregatedSslFlow const*>(b);
        return aCast->numConnections < bCast->numConnections;
    }

    [[nodiscard]] static auto sortByConnectionP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = static_cast<AggregatedSslFlow const*>(b);
        return aCast->connections.getPercentile(.95) < bCast->connections.getPercentile(.95);
    }

    [[nodiscard]] static auto sortByConnectionP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = static_cast<AggregatedSslFlow const*>(b);
        return aCast->connections.getPercentile(.99) < bCast->connections.getPercentile(.99);
    }

    [[nodiscard]] static auto sortByDomain(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = static_cast<AggregatedSslFlow const*>(b);
        return aCast->domain < bCast->domain;
    }

    [[nodiscard]] static auto sortByCipherSuite(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = static_cast<AggregatedSslFlow const*>(b);
        return aCast->sslCipherSuite < bCast->sslCipherSuite;
    }

    [[nodiscard]] static auto sortByTlsVersion(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = static_cast<AggregatedSslFlow const*>(b);
        return aCast->tlsVersion < bCast->tlsVersion;
    }

private:
    std::string domain;
    int numConnections = 0;
    int totalConnections = 0;
    Percentile connections;
    TLSVersion tlsVersion;
    std::optional<SSLCipherSuite> sslCipherSuite;
};
} // namespace flowstats
