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
    SslStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration const& displayConf);
    ~SslStatsCollector() override;

    auto processPacket(Tins::Packet const& packet) -> void override;
    auto resetMetrics() -> void override;

    auto getProtocol() -> CollectorProtocol override { return SSL; };
    auto toString() -> std::string override { return "SslStatsCollector"; }

    [[nodiscard]] auto getAggregatedPairs() const -> std::vector<AggregatedPairPointer> override;
    [[nodiscard]] auto getAggregatedMap() const -> std::map<AggregatedTcpKey, AggregatedSslFlow*> { return aggregatedMap; }
    [[nodiscard]] auto getSslFlow() const -> std::map<uint32_t, SslFlow> { return hashToSslFlow; }
    void mergePercentiles() override;

private:
    std::map<uint32_t, SslFlow> hashToSslFlow;
    std::map<AggregatedTcpKey, AggregatedSslFlow*> aggregatedMap;
    auto lookupSslFlow(FlowId const& flowId) -> SslFlow&;
    auto lookupAggregatedFlows(SslFlow const& sslFlow,
        FlowId const& flowId,
        std::string const& fqdn) -> std::vector<AggregatedSslFlow*>;
};
}
