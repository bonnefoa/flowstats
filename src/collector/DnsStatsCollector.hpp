#pragma once

#include "AggregatedDnsFlow.hpp"
#include "Collector.hpp"
#include "Configuration.hpp"
#include "DnsFlow.hpp"
#include "Utils.hpp"
#include <spdlog/spdlog.h>

namespace flowstats {

class DnsStatsCollector : public Collector {
public:
    DnsStatsCollector(FlowstatsConfiguration& conf,
        DisplayConfiguration& displayConf);
    ~DnsStatsCollector();

    auto processPacket(const Tins::Packet& packet) -> void override;
    auto getMetrics() -> std::vector<std::string> override;
    auto toString() -> std::string override { return "DnsStatsCollector"; }
    std::map<AggregatedDnsKey, AggregatedDnsFlow*> getAggregatedFlow()
    {
        return aggregatedDnsFlows;
    }
    auto advanceTick(timeval now) -> void override;
    auto resetMetrics() -> void override;
    auto getAggregatedPairs() -> std::vector<AggregatedPairPointer> const override;
    auto mergePercentiles() -> void override;
    auto getProtocol() -> CollectorProtocol override { return DNS; };

private:
    auto newDnsQuery(const Tins::Packet& packet, const Tins::DNS& dns) -> void;
    auto newDnsResponse(const Tins::Packet& packet, const Tins::DNS& dns, DnsFlow& flow) -> void;
    auto updateIpToFqdn(const Tins::DNS& dns, const std::string& fqdn) -> void;

    void addFlowToAggregation(DnsFlow& flow);
    std::map<uint16_t, DnsFlow> transactionIdToDnsFlow;
    std::vector<DnsFlow> dnsFlows;
    std::map<AggregatedDnsKey, AggregatedDnsFlow*> aggregatedDnsFlows;
    time_t lastTick = 0;
};
}
