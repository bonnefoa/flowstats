#pragma once

#include "AggregatedDnsFlow.hpp"
#include "Collector.hpp"
#include "Configuration.hpp"
#include "DnsFlow.hpp"
#include "IpToFqdn.hpp"
#include "Utils.hpp"
#include <spdlog/spdlog.h>

namespace flowstats {

class DnsStatsCollector : public Collector {
public:
    DnsStatsCollector(FlowstatsConfiguration const& conf,
        DisplayConfiguration const& displayConf,
        IpToFqdn* ipToFqdn);
    ~DnsStatsCollector() override;

    auto processPacket(Tins::Packet const& packet) -> void override;
    auto getMetrics() -> std::vector<std::string> override;
    auto advanceTick(timeval now) -> void override;
    auto resetMetrics() -> void override;
    auto mergePercentiles() -> void override;

    auto toString() -> std::string override { return "DnsStatsCollector"; }
    [[nodiscard]] auto getAggregatedPairs() const -> std::vector<AggregatedPairPointer> override;
    [[nodiscard]] auto getAggregatedFlow() const { return aggregatedDnsFlows; }
    auto getProtocol() -> CollectorProtocol override { return DNS; };

private:
    auto newDnsQuery(Tins::Packet const& packet, Tins::DNS const& dns) -> void;
    auto newDnsResponse(Tins::Packet const& packet, Tins::DNS const& dns, DnsFlow* flow) -> void;
    auto updateIpToFqdn(Tins::DNS const& dns, std::string const& fqdn) -> void;

    auto addFlowToAggregation(DnsFlow const* flow) -> void;
    IpToFqdn* ipToFqdn;
    std::map<uint16_t, DnsFlow> transactionIdToDnsFlow;
    std::map<AggregatedDnsKey, AggregatedDnsFlow*> aggregatedDnsFlows;
    time_t lastTick = 0;
};
} // namespace flowstats
