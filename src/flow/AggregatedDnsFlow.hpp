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
    {
        fqdn = "Total";
    };

    AggregatedDnsFlow(FlowId const& flowId, std::string fqdn,
        enum Tins::DNS::QueryType dnsType)
        : Flow(flowId, fqdn)
        , dnsType(dnsType) {};

    auto resetFlow(bool resetTotal) -> void override;
    auto operator<(AggregatedDnsFlow const& b) { return queries < b.queries; }
    auto fillValues(std::map<Field, std::string>& values,
        Direction direction, int duration) const -> void override;
    auto addFlow(Flow const* flow) -> void override;
    auto addAggregatedFlow(Flow const* flow) -> void override;
    auto getStatsdMetrics() const -> std::vector<std::string>;
    auto mergePercentiles() -> void { srts.merge(); }

    auto sortBySrt(AggregatedDnsFlow const& b) const -> bool
    {
        return srts.getPercentile(1.0) < b.srts.getPercentile(1.0);
    }

    auto sortByRequest(AggregatedDnsFlow const& b) const -> bool
    {
        return totalQueries < b.totalQueries;
    }

    auto sortByRequestRate(AggregatedDnsFlow const& b) const -> bool
    {
        return srts.getCount() < b.srts.getCount();
    }

private:
    [[nodiscard]] auto getTopClientIps() const -> std::vector<std::pair<int, int>>;
    [[nodiscard]] auto getTopClientIpsStr() const -> std::string;

    enum Tins::DNS::QueryType dnsType;

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

struct AggregatedDnsKey : AggregatedKey {
    AggregatedDnsKey(std::string _fqdn, Tins::DNS::QueryType _dnsType, Transport transport)
        : AggregatedKey(_fqdn)
        , dnsType(_dnsType)
        , transport(transport) {};

    auto operator<(AggregatedDnsKey const& b) const -> bool
    {
        return std::tie(fqdn, dnsType, transport) < std::tie(b.fqdn, b.dnsType, b.transport);
    }

private:
    Tins::DNS::QueryType dnsType;
    Transport transport;
};
} // namespace flowstats
