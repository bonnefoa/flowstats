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
        Direction direction, int duration) const -> void override;
    auto addFlow(Flow const* flow) -> void override;
    auto addAggregatedFlow(Flow const* flow) -> void override;
    auto mergePercentiles() -> void override { srts.merge(); }

    [[nodiscard]] auto getStatsdMetrics() const -> std::vector<std::string> override;
    [[nodiscard]] static auto sortBySrt(Flow const* a, Flow const* b) -> bool
    {
        auto aCast = static_cast<AggregatedDnsFlow const*>(a);
        auto bCast = static_cast<AggregatedDnsFlow const*>(b);
        return aCast->srts.getPercentile(1.0) < bCast->srts.getPercentile(1.0);
    }

    [[nodiscard]] static auto sortByRequest(Flow const* a, Flow const* b) -> bool
    {
        auto aCast = static_cast<AggregatedDnsFlow const*>(a);
        auto bCast = static_cast<AggregatedDnsFlow const*>(b);
        return aCast->totalQueries < bCast->totalQueries;
    }

    [[nodiscard]] static auto sortByRequestRate(Flow const* a, Flow const* b) -> bool
    {
        auto aCast = static_cast<AggregatedDnsFlow const*>(a);
        auto bCast = static_cast<AggregatedDnsFlow const*>(b);
        return aCast->srts.getCount() < bCast->srts.getCount();
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
