#pragma once

#include "AggregatedFlow.hpp"
#include "DnsFlow.hpp"
#include "Stats.hpp"
#include <map>
#include <spdlog/spdlog.h>
#include <string>

namespace flowstats {

struct AggregatedDnsFlow : Flow {
    enum pcpp::DnsType dnsType;
    bool isTcp = false;

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

    AggregatedDnsFlow(FlowId& flowId, std::string fqdn,
        enum pcpp::DnsType dnsType, bool isTcp)
        : Flow(flowId, fqdn)
        , dnsType(dnsType)
        , isTcp(isTcp) {};

    void resetFlow(bool resetTotal);
    bool operator<(AggregatedDnsFlow const& b) { return queries < b.queries; }
    void fillValues(std::map<std::string, std::string>& values, Direction direction, int duration);
    void addFlow(Flow* flow);
    void addAggregatedFlow(Flow* flow);

private:
    std::vector<std::pair<int, int>> getTopClientIps();
    std::string getTopClientIpsStr();
};

struct AggregatedDnsKey : AggregatedKey {
    AggregatedDnsKey(std::string _fqdn, pcpp::DnsType _dnsType, bool _isTcp)
        : AggregatedKey(_fqdn)
        , dnsType(_dnsType)
        , isTcp(_isTcp) {};

    bool operator<(AggregatedDnsKey const& b) const
    {
        return std::tie(fqdn, dnsType, isTcp) < std::tie(b.fqdn, b.dnsType, b.isTcp);
    }

private:
    pcpp::DnsType dnsType;
    bool isTcp;
};
}
