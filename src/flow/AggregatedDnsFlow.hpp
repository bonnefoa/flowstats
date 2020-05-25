#pragma once

#include "AggregatedFlow.hpp"
#include "DnsFlow.hpp"
#include "Stats.hpp"
#include <map>
#include <spdlog/spdlog.h>
#include <string>

namespace flowstats {

struct AggregatedDnsFlow : Flow {

    AggregatedDnsFlow()
        : Flow("Total") {};

    AggregatedDnsFlow(FlowId const& flowId, std::string const& fqdn,
        enum Tins::DNS::QueryType dnsType)
        : Flow(flowId, fqdn)
        , dnsType(dnsType) {};

    auto resetFlow(bool resetTotal) -> void override;
    auto operator<(AggregatedDnsFlow const& b) { return queries < b.queries; }
    auto fillValues(std::map<Field, std::string>& values,
        Direction direction) const -> void override;
    auto addFlow(Flow const* flow) -> void override;
    auto addAggregatedFlow(Flow const* flow) -> void override;
    auto mergePercentiles() -> void override { srts.merge(); }

    [[nodiscard]] auto getStatsdMetrics() const -> std::vector<std::string> override;

    [[nodiscard]] static auto sortByRequest(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->totalQueries < bCast->totalQueries;
    }

    [[nodiscard]] static auto sortByRequestRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->srts.getCount() < bCast->srts.getCount();
    }

    [[nodiscard]] static auto sortByTimeout(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->totalTimeouts < bCast->totalTimeouts;
    }

    [[nodiscard]] static auto sortByTimeoutRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->timeouts < bCast->timeouts;
    }

    [[nodiscard]] static auto sortByProto(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->getFlowId().getTransport() < bCast->getFlowId().getTransport();
    }

    [[nodiscard]] static auto sortByType(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->dnsType < bCast->dnsType;
    }

    [[nodiscard]] static auto sortBySrt(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->totalSrt < bCast->totalSrt;
    }

    [[nodiscard]] static auto sortBySrtRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->numSrt < bCast->numSrt;
    }

    [[nodiscard]] static auto sortBySrtP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->srts.getPercentile(0.95) < bCast->srts.getPercentile(0.95);
    }

    [[nodiscard]] static auto sortBySrtP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->srts.getPercentile(0.99) < bCast->srts.getPercentile(0.99);
    }

    [[nodiscard]] static auto sortBySrtMax(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->srts.getPercentile(1) < bCast->srts.getPercentile(1);
    }

    [[nodiscard]] static auto sortByRcrdAvg(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedDnsFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedDnsFlow const*>(b);
        return aCast->totalRecords / aCast->totalQueries < bCast->totalRecords / bCast->totalQueries;
    }

private:
    [[nodiscard]] auto getTopClientIps() const -> std::vector<std::pair<int, int>>;
    [[nodiscard]] auto getTopClientIpsStr() const -> std::string;

    enum Tins::DNS::QueryType dnsType = Tins::DNS::QueryType::A;

    int totalQueries = 0;
    int totalResponses = 0;
    int totalTruncated = 0;
    int totalTimeouts = 0;
    int totalRecords = 0;

    int queries = 0;
    int timeouts = 0;
    int truncated = 0;
    uint16_t records = 0;

    int numSrt = 0;
    int totalSrt = 0;
    std::map<int, int> sourceIps;
    Percentile srts;
};

} // namespace flowstats
