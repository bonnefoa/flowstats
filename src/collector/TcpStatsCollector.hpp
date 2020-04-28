#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Collector.hpp"
#include "TcpFlow.hpp"

namespace flowstats {

class TcpStatsCollector : public Collector {
public:
    TcpStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration const& displayConf);
    ~TcpStatsCollector() override;

    auto processPacket(Tins::Packet const& packet) -> void override;
    auto resetMetrics() -> void override;

    auto advanceTick(timeval now) -> void override;
    auto getMetrics() -> std::vector<std::string> override;
    auto mergePercentiles() -> void override;

    auto getProtocol() -> CollectorProtocol override { return TCP; };
    auto toString() -> std::string override { return "TcpStatsCollector"; }

    [[nodiscard]] auto getAggregatedPairs() const -> std::vector<AggregatedPairPointer> override;
    [[nodiscard]] auto getAggregatedMap() const { return aggregatedMap; }
    [[nodiscard]] auto getTcpFlow() const { return hashToTcpFlow; }

    int lastTick = 0;

private:
    std::map<size_t, TcpFlow> hashToTcpFlow;
    std::map<uint16_t, int> srvPortsCounter;

    std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap;
    std::vector<std::pair<TcpFlow*, std::vector<AggregatedTcpFlow*>>> openingTcpFlow;
    auto lookupTcpFlow(Tins::IP const& ipv4Layer,
        Tins::TCP const& tcpLayer,
        FlowId const& flowId) -> TcpFlow&;
    auto lookupAggregatedFlows(TcpFlow& tcp, FlowId const& flowId) -> std::vector<AggregatedTcpFlow*>;

    void timeoutOpeningConnections(timeval now);
    void timeoutFlows(timeval now);
};
} // namespace flowstats
