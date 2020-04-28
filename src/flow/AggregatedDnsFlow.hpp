#pragma once

#include "AggregatedFlow.hpp"
#include "DnsFlow.hpp"
#include "Stats.hpp"
#include <map>
#include <spdlog/spdlog.h>
#include <string>

namespace flowstats {

struct AggregatedDnsFlow : Flow {
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
    auto fillValues(std::map<std::string, std::string>& values,
        Direction direction, int duration) -> void override;
    auto addFlow(Flow const* flow) -> void override;
    auto addAggregatedFlow(Flow const* flow) -> void override;

private:
    std::vector<std::pair<int, int>> getTopClientIps();
    std::string getTopClientIpsStr();
};

struct AggregatedDnsKey : AggregatedKey {
    AggregatedDnsKey(std::string _fqdn, Tins::DNS::QueryType _dnsType, bool _isTcp)
        : AggregatedKey(_fqdn)
        , dnsType(_dnsType)
        , isTcp(_isTcp) {};

    bool operator<(AggregatedDnsKey const& b) const
    {
        return std::tie(fqdn, dnsType, isTcp) < std::tie(b.fqdn, b.dnsType, b.isTcp);
    }

private:
    Tins::DNS::QueryType dnsType;
    bool isTcp;
};
} // namespace flowstats
