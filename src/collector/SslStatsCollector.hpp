#pragma once

#include "AggregatedSslFlow.hpp"
#include "Collector.hpp"
#include "PrintHelper.hpp"
#include "SslFlow.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <iostream>
#include <map>
#include <sstream>

namespace flowstats {

using hashFlow = std::pair<uint32_t, SslFlow>;

class SslStatsCollector : public Collector {
public:
    SslStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration& displayConf);
    ~SslStatsCollector();

    auto processPacket(const Tins::Packet& packet) -> void override;
    auto resetMetrics() -> void override;

    auto getProtocol() -> CollectorProtocol override { return SSL; };
    auto getAggregatedPairs() -> std::vector<AggregatedPairPointer> const override;
    auto toString() -> std::string override { return "SslStatsCollector"; }

    std::map<AggregatedTcpKey, AggregatedSslFlow*> getAggregatedMap() { return aggregatedMap; }
    std::map<uint32_t, SslFlow> getSslFlow() { return hashToSslFlow; }
    void mergePercentiles() override;

private:
    std::map<uint32_t, SslFlow> hashToSslFlow;
    std::map<AggregatedTcpKey, AggregatedSslFlow*> aggregatedMap;
    SslFlow& lookupSslFlow(const Tins::IP& ipv4Layer,
        const Tins::TCP& tcp, FlowId& flowId);

    std::vector<AggregatedSslFlow*> lookupAggregatedFlows(const Tins::TCP& tcp,
        SslFlow& sslFlow, FlowId& flowId,
        const std::string& fqdn);
};
}
