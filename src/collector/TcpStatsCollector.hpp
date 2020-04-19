#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Collector.hpp"
#include "TcpFlow.hpp"
#include <stdlib.h>

namespace flowstats {

class TcpStatsCollector : public Collector {
public:
    TcpStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration& displayConf);
    ~TcpStatsCollector();

    void processPacket(pcpp::Packet* packet);

    void resetMetrics();

    std::string getFlowName() { return "TCP"; }
    pcpp::ProtocolType getProtocol() { return pcpp::TCP; };
    std::string toString() { return "TcpStatsCollector"; }

    std::vector<Flow*> getFlows()
    {
        std::vector<Flow*> res;
        return res;
    }

    std::map<AggregatedTcpKey, AggregatedTcpFlow*> getAggregatedMap()
    {
        return aggregatedMap;
    }

    std::map<uint32_t, TcpFlow> getTcpFlow() { return hashToTcpFlow; }
    std::vector<AggregatedPairPointer> getAggregatedPairs();
    int lastTick = 0;
    void advanceTick(timespec now);
    std::vector<std::string> getMetrics();
    void mergePercentiles();

private:
    std::map<uint32_t, TcpFlow> hashToTcpFlow;
    std::map<uint16_t, int> srvPortsCounter;
    void timeoutFlow(TcpFlow* flow);

    std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap;
    std::vector<std::pair<TcpFlow*, std::vector<AggregatedTcpFlow*>>> openingTcpFlow;
    TcpFlow& lookupTcpFlow(pcpp::IPv4Layer* ipv4Layer,
        pcpp::TcpLayer* tcpLayer,
        FlowId& flowId);
    std::vector<AggregatedTcpFlow*> lookupAggregatedFlows(TcpFlow& tcp, FlowId& flowId);

    void timeoutOpeningConnections(timespec now);
    void timeoutFlows(timespec now);
};
}
