#pragma once

#include "DnsFlow.hpp"
#include "Stats.hpp"
#include <map>
#include <string>

namespace flowstats {

class TrafficStatsDns {
public:
    uint64_t bytes = 0;
    uint64_t pkts = 0;
    uint64_t requests = 0;

    enum TrafficType {
        BYTES,
        PKTS,
        REQUESTS,
    };
};

struct DnsAggregatedFlow : Flow {

    DnsAggregatedFlow()
        : Flow("Total") {};

    DnsAggregatedFlow(FlowId const& flowId, std::string const& fqdn,
        enum Tins::DNS::QueryType dnsType)
        : Flow(flowId, fqdn)
        , dnsType(dnsType) {};

    auto resetFlow(bool resetTotal) -> void override;
    auto operator<(DnsAggregatedFlow const& b) { return queries < b.queries; }
    auto addFlow(Flow const* flow) -> void override;
    auto addAggregatedFlow(Flow const* flow) -> void override;
    auto mergePercentiles() -> void override { srts.merge(); }
    auto prepareSubfields(std::vector<Field> const& fields) -> void override;

    [[nodiscard]] auto getFieldStr(Field field, Direction direction, int duration, int index) const -> std::string override;
    [[nodiscard]] auto getSubfieldSize(Field field) const -> int override;

    [[nodiscard]] static auto sortByRequest(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<DnsAggregatedFlow const*>(a);
        auto const* bCast = static_cast<DnsAggregatedFlow const*>(b);
        return aCast->totalQueries < bCast->totalQueries;
    }

    [[nodiscard]] static auto sortByRequestRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<DnsAggregatedFlow const*>(a);
        auto const* bCast = static_cast<DnsAggregatedFlow const*>(b);
        return aCast->srts.getCount() < bCast->srts.getCount();
    }

    [[nodiscard]] static auto sortByTimeout(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<DnsAggregatedFlow const*>(a);
        auto const* bCast = static_cast<DnsAggregatedFlow const*>(b);
        return aCast->totalTimeouts < bCast->totalTimeouts;
    }

    [[nodiscard]] static auto sortByTimeoutRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<DnsAggregatedFlow const*>(a);
        auto const* bCast = static_cast<DnsAggregatedFlow const*>(b);
        return aCast->timeouts < bCast->timeouts;
    }

    [[nodiscard]] static auto sortByProto(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<DnsAggregatedFlow const*>(a);
        auto const* bCast = static_cast<DnsAggregatedFlow const*>(b);
        return aCast->getFlowId().getTransport() < bCast->getFlowId().getTransport();
    }

    [[nodiscard]] static auto sortByType(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<DnsAggregatedFlow const*>(a);
        auto const* bCast = static_cast<DnsAggregatedFlow const*>(b);
        return aCast->dnsType < bCast->dnsType;
    }

    [[nodiscard]] static auto sortBySrt(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<DnsAggregatedFlow const*>(a);
        auto const* bCast = static_cast<DnsAggregatedFlow const*>(b);
        return aCast->totalNumSrt < bCast->totalNumSrt;
    }

    [[nodiscard]] static auto sortBySrtRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<DnsAggregatedFlow const*>(a);
        auto const* bCast = static_cast<DnsAggregatedFlow const*>(b);
        return aCast->numSrt < bCast->numSrt;
    }

    [[nodiscard]] static auto sortBySrtPercentile(Flow const* a, Flow const* b,
            float percentile, bool total) -> bool
    {
        auto const* aCast = static_cast<DnsAggregatedFlow const*>(a);
        auto const* bCast = static_cast<DnsAggregatedFlow const*>(b);
        auto& aPercentile = total? aCast->totalSrts : aCast->srts;
        auto& bPercentile = total? bCast->totalSrts : bCast->srts;
        return aPercentile.getPercentile(percentile) < bPercentile.getPercentile(percentile);
    }

    [[nodiscard]] static auto sortByResourceRecord(Flow const* a, Flow const* b, ResourceRecordType rrType, bool total) -> bool
    {
        auto const* aCast = static_cast<DnsAggregatedFlow const*>(a);
        auto const* bCast = static_cast<DnsAggregatedFlow const*>(b);
        auto& aResourceRecords = total ? aCast->resourceRecords : aCast->totalResourceRecords;
        auto& bResourceRecords = total ? bCast->resourceRecords : bCast->totalResourceRecords;
        return aResourceRecords.getResourceRecordCount(rrType) < bResourceRecords.getResourceRecordCount(rrType);
    }

private:
    auto computeTopClientIps(TrafficStatsDns::TrafficType type) -> void;
    [[nodiscard]] auto getTopClientIpsKey(int index) const -> std::string;
    [[nodiscard]] auto getTopClientIpsValue(TrafficStatsDns::TrafficType type, int index) const -> std::string;
    std::vector<std::pair<IPAddress, TrafficStatsDns>> topClientIps;

    enum Tins::DNS::QueryType dnsType = Tins::DNS::QueryType::A;

    int totalQueries = 0;
    int totalResponses = 0;
    int totalTruncated = 0;
    int totalTimeouts = 0;
    ResourceRecords totalResourceRecords;

    int queries = 0;
    int timeouts = 0;
    int truncated = 0;
    ResourceRecords resourceRecords;

    int numSrt = 0;
    int totalNumSrt = 0;
    std::map<IPAddress, TrafficStatsDns> sourceIpToStats;

    Percentile srts;
    Percentile totalSrts;
};

} // namespace flowstats
