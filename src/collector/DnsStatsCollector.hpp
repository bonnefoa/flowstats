#pragma once

#include "AggregatedDnsFlow.hpp"
#include "AggregatedKeys.hpp"
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
    auto advanceTick(timeval now) -> void override;

    auto toString() const -> std::string override { return "DnsStatsCollector"; }
    [[nodiscard]] auto getAggregatedFlow() const { return aggregatedDnsFlows; }
    auto getProtocol() const -> CollectorProtocol override { return DNS; };
    auto getSortFun(Field field) const -> Flow::sortFlowFun override;

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
