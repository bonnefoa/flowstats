#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Collector.hpp"
#include "TcpFlow.hpp"

namespace flowstats {

class TcpStatsCollector : public Collector {
public:
    TcpStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration& displayConf);
    ~TcpStatsCollector();

    void processPacket(const Tins::Packet& packet) override;

    void resetMetrics() override;

    auto getProtocol() -> CollectorProtocol override { return TCP; };
    auto toString() -> std::string override { return "TcpStatsCollector"; }

    std::map<AggregatedTcpKey, AggregatedTcpFlow*> getAggregatedMap()
    {
        return aggregatedMap;
    }

    std::map<size_t, TcpFlow> getTcpFlow() { return hashToTcpFlow; }
    auto getAggregatedPairs() -> std::vector<AggregatedPairPointer> const override;
    int lastTick = 0;
    auto advanceTick(timeval now) -> void override;
    auto getMetrics() -> std::vector<std::string> override;
    auto mergePercentiles() -> void override;

private:
    std::map<size_t, TcpFlow> hashToTcpFlow;
    std::map<uint16_t, int> srvPortsCounter;
    void timeoutFlow(TcpFlow* flow);

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
