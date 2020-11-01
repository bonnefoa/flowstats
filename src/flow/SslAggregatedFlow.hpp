#pragma once

#include "Flow.hpp"
#include "SslProto.hpp"
#include "Stats.hpp"

namespace flowstats {

class SslAggregatedFlow : public Flow {
public:
    SslAggregatedFlow()
        : Flow("Total")
        , tlsVersion(TLSVersion::UNKNOWN) {};

    SslAggregatedFlow(FlowId const& flowId, std::string const& fqdn)
        : Flow(flowId, fqdn)
        , tlsVersion(TLSVersion::UNKNOWN) {};

    auto resetFlow(bool resetTotal) -> void override;
    auto setTlsVersion(TLSVersion tlsVers) -> void;
    auto setDomain(std::string _domain) -> void { domain = std::move(_domain); }
    auto setSslCipherSuite(SSLCipherSuite _sslCipherSuite) -> void { sslCipherSuite = _sslCipherSuite; }
    auto addConnection(int delta) -> void;
    auto merge() -> void { connectionTimes.merge(); };

    [[nodiscard]] auto getFieldStr(Field field, Direction direction, int duration, int index) const -> std::string override;
    [[nodiscard]] auto getDomain() const { return domain; }

    [[nodiscard]] static auto sortByConnections(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<SslAggregatedFlow const*>(a);
        auto const* bCast = static_cast<SslAggregatedFlow const*>(b);
        return aCast->totalConnections < bCast->totalConnections;
    }

    [[nodiscard]] static auto sortByConnectionRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<SslAggregatedFlow const*>(a);
        auto const* bCast = static_cast<SslAggregatedFlow const*>(b);
        return aCast->numConnections < bCast->numConnections;
    }

    [[nodiscard]] static auto sortByConnectionP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<SslAggregatedFlow const*>(a);
        auto const* bCast = static_cast<SslAggregatedFlow const*>(b);
        return aCast->connectionTimes.getPercentile(.95) < bCast->connectionTimes.getPercentile(.95);
    }

    [[nodiscard]] static auto sortByConnectionTotalP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<SslAggregatedFlow const*>(a);
        auto const* bCast = static_cast<SslAggregatedFlow const*>(b);
        return aCast->totalConnectionTimes.getPercentile(.95) < bCast->totalConnectionTimes.getPercentile(.95);
    }

    [[nodiscard]] static auto sortByConnectionP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<SslAggregatedFlow const*>(a);
        auto const* bCast = static_cast<SslAggregatedFlow const*>(b);
        return aCast->connectionTimes.getPercentile(.99) < bCast->connectionTimes.getPercentile(.99);
    }

    [[nodiscard]] static auto sortByConnectionTotalP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<SslAggregatedFlow const*>(a);
        auto const* bCast = static_cast<SslAggregatedFlow const*>(b);
        return aCast->totalConnectionTimes.getPercentile(.99) < bCast->totalConnectionTimes.getPercentile(.99);
    }

    [[nodiscard]] static auto sortByDomain(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<SslAggregatedFlow const*>(a);
        auto const* bCast = static_cast<SslAggregatedFlow const*>(b);
        return aCast->domain < bCast->domain;
    }

    [[nodiscard]] static auto sortByCipherSuite(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<SslAggregatedFlow const*>(a);
        auto const* bCast = static_cast<SslAggregatedFlow const*>(b);
        return aCast->sslCipherSuite < bCast->sslCipherSuite;
    }

    [[nodiscard]] static auto sortByTlsVersion(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<SslAggregatedFlow const*>(a);
        auto const* bCast = static_cast<SslAggregatedFlow const*>(b);
        return aCast->tlsVersion < bCast->tlsVersion;
    }

private:
    std::string domain;
    int numConnections = 0;
    // TODO
    //int activeConnections = 0;
    int totalConnections = 0;
    Percentile connectionTimes;
    Percentile totalConnectionTimes;
    TLSVersion tlsVersion;
    std::optional<SSLCipherSuite> sslCipherSuite;
};
} // namespace flowstats
