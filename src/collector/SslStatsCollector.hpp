#pragma once

#include "AggregatedSslFlow.hpp"
#include "Collector.hpp"
#include "PrintHelper.hpp"
#include "SslFlow.hpp"
#include <PacketUtils.h>
#include <PayloadLayer.h>
#include <SSLLayer.h>
#include <SystemUtils.h>
#include <TcpLayer.h>
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

    void processPacket(pcpp::Packet* packet);
    void resetMetrics();

    std::string getFlowName() { return "SSL"; }
    pcpp::ProtocolType getProtocol() { return pcpp::SSL; };
    std::string toString() { return "SslStatsCollector"; }
    std::vector<AggregatedPairPointer> getAggregatedPairs();

    std::vector<Flow*> getFlows();
    std::map<AggregatedTcpKey, AggregatedSslFlow*> getAggregatedMap() { return aggregatedMap; }
    std::map<uint32_t, SslFlow> getSslFlow() { return hashToSslFlow; }
    void mergePercentiles();

private:
    std::map<uint32_t, SslFlow> hashToSslFlow;
    std::map<AggregatedTcpKey, AggregatedSslFlow*> aggregatedMap;
    SslFlow& lookupSslFlow(pcpp::IPv4Layer* ipv4Layer,
        pcpp::TcpLayer* tcpLayer, FlowId& flowId);

    std::vector<AggregatedSslFlow*> lookupAggregatedFlows(pcpp::TcpLayer* tcpLayer,
        SslFlow& sslFlow, FlowId& flowId,
        const std::string& fqdn);
};
}
