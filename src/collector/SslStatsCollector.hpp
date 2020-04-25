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
    auto getAggregatedPairs() const -> std::vector<AggregatedPairPointer> override;
    auto toString() -> std::string override { return "SslStatsCollector"; }

    auto getAggregatedMap() const -> std::map<AggregatedTcpKey, AggregatedSslFlow*> { return aggregatedMap; }
    auto getSslFlow() const -> std::map<uint32_t, SslFlow> { return hashToSslFlow; }
    void mergePercentiles() override;

private:
    std::map<uint32_t, SslFlow> hashToSslFlow;
    std::map<AggregatedTcpKey, AggregatedSslFlow*> aggregatedMap;
    auto lookupSslFlow(const Tins::IP& ipv4Layer,
        const Tins::TCP& tcp, FlowId& flowId) -> SslFlow&;
    auto lookupAggregatedFlows(const Tins::TCP& tcp,
        SslFlow& sslFlow, FlowId& flowId,
        const std::string& fqdn) -> std::vector<AggregatedSslFlow*>;
};
}
