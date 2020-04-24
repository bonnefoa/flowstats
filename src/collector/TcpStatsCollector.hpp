#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Collector.hpp"
#include "TcpFlow.hpp"

namespace flowstats {

class TcpStatsCollector : public Collector {
public:
    TcpStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration& displayConf);
    ~TcpStatsCollector();

    auto processPacket(const Tins::Packet& packet) -> void override;
    auto resetMetrics() -> void override;

    auto getAggregatedPairs() -> std::vector<AggregatedPairPointer> const override;
    auto advanceTick(timeval now) -> void override;
    auto getMetrics() -> std::vector<std::string> override;
    auto mergePercentiles() -> void override;

    auto getProtocol() -> CollectorProtocol override { return TCP; };
    auto toString() -> std::string override { return "TcpStatsCollector"; }
    auto getAggregatedMap() const { return aggregatedMap; }
    auto getTcpFlow() const { return hashToTcpFlow; }

    int lastTick = 0;

private:
    std::map<size_t, TcpFlow> hashToTcpFlow;
    std::map<uint16_t, int> srvPortsCounter;

    std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap;
    std::vector<std::pair<TcpFlow*, std::vector<AggregatedTcpFlow*>>> openingTcpFlow;
    TcpFlow& lookupTcpFlow(const Tins::IP& ipv4Layer,
        const Tins::TCP& tcpLayer,
        const FlowId& flowId);
    std::vector<AggregatedTcpFlow*> lookupAggregatedFlows(TcpFlow& tcp, const FlowId& flowId);

    void timeoutOpeningConnections(timeval now);
    void timeoutFlows(timeval now);
};
}
