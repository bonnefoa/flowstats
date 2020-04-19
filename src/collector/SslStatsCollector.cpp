#include "SslStatsCollector.hpp"
#include <fmt/format.h>
#include <spdlog/spdlog.h>

namespace flowstats {

SslStatsCollector::SslStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration& displayConf)
    : Collector { conf, displayConf }
{
    if (conf.perIpAggr) {
        flowFormatter.setDisplayKeys({ "fqdn", "ip", "port", "dir" });
    } else {
        flowFormatter.setDisplayKeys({ "fqdn", "port", "dir" });
    }
    flowFormatter.setDisplayValues({ "conn", "conn_s",
        "ctp95", "ctp99",
        "tickets",
        "pkts", "pkts_s",
        "bytes", "bytes_s" });

    displayPairs = {
        DisplayPair(DisplayConnections, { "conn", "conn_s", "ctp95", "ctp99" }),
        DisplayPair(DisplayTraffic, { "pkts", "pkts_s", "bytes", "bytes_s" }),
    };
    totalFlow = new AggregatedSslFlow();
    updateDisplayType(0);
};

auto SslStatsCollector::lookupSslFlow(
    pcpp::IPv4Layer* ipv4Layer,
    pcpp::TcpLayer* tcpLayer,
    FlowId& flowId) -> SslFlow&
{
    uint32_t hashVal = hash5Tuple(ipv4Layer, tcpLayer);
    SslFlow& sslFlow = hashToSslFlow[hashVal];
    if (sslFlow.flowId.ports[0] == 0) {
        spdlog::debug("Create ssl flow {}", flowId.toString());
        sslFlow.flowId = flowId;
        std::optional<std::string> fqdn = getFlowFqdn(conf, sslFlow.getSrvIpInt());
        if (!fqdn.has_value()) {
            return sslFlow;
        }
        sslFlow.aggregatedFlows = lookupAggregatedFlows(tcpLayer, sslFlow, flowId, fqdn->data());
    }
    return sslFlow;
}

auto SslStatsCollector::lookupAggregatedFlows(
    pcpp::TcpLayer*  /*tcpLayer*/, SslFlow& sslFlow, FlowId& flowId,
    const std::string& fqdn) -> std::vector<AggregatedSslFlow*>
{
    std::vector<AggregatedSslFlow*> subflows;
    IPv4 ipSrvInt = 0;
    if (conf.perIpAggr) {
        ipSrvInt = sslFlow.getSrvIpInt();
    }
    AggregatedTcpKey tcpKey = AggregatedTcpKey(fqdn, ipSrvInt, sslFlow.getSrvPort());
    AggregatedSslFlow* aggregatedFlow;

    auto it = aggregatedMap.find(tcpKey);
    if (it == aggregatedMap.end()) {
        aggregatedFlow = new AggregatedSslFlow(flowId, fqdn);
        aggregatedMap[tcpKey] = aggregatedFlow;
    } else {
        aggregatedFlow = it->second;
    }
    subflows.push_back(aggregatedFlow);

    return subflows;
}

void SslStatsCollector::processPacket(pcpp::Packet* packet)
{
    advanceTick(packet->getRawPacket()->getPacketTimeStamp());
    if (!packet->isPacketOfType(pcpp::TCP) || packet->isPacketOfType(pcpp::IPv6) || !packet->isPacketOfType(pcpp::SSL)) {
        return;
    }

    auto* sslLayer = packet->getLayerOfType<pcpp::SSLLayer>(true);
    auto* tcpLayer = packet->getPrevLayerOfType<pcpp::TcpLayer>(sslLayer);
    auto* ipv4Layer = packet->getPrevLayerOfType<pcpp::IPv4Layer>(tcpLayer);

    FlowId flowId(ipv4Layer, tcpLayer);
    SslFlow& sslFlow = lookupSslFlow(ipv4Layer, tcpLayer, flowId);
    sslFlow.addPacket(packet, flowId.direction);
    for (auto& subflow : sslFlow.aggregatedFlows) {
        subflow->addPacket(packet, flowId.direction);
    }

    const std::lock_guard<std::mutex> lock(*getDataMutex());

    sslFlow.updateFlow(packet, flowId.direction, sslLayer);
}

void SslStatsCollector::resetMetrics()
{
    const std::lock_guard<std::mutex> lock(*getDataMutex());
    for (auto& pair : aggregatedMap) {
        pair.second->resetFlow(false);
    }
}

void SslStatsCollector::mergePercentiles()
{
    for (auto& i : aggregatedMap) {
        i.second->connections.merge();
    }
}

auto SslStatsCollector::getFlows() -> std::vector<Flow*>
{
    std::vector<Flow*> res;
    for (auto& pair : hashToSslFlow) {
        res.push_back(&pair.second);
    }
    return res;
}

auto SslStatsCollector::getAggregatedPairs() -> std::vector<AggregatedPairPointer>
{
    std::vector<AggregatedPairPointer> tempVector;

    for (auto& pair : aggregatedMap) {
        pair.second->connections.merge();
        tempVector.emplace_back( pair.first, pair.second );
    }

    spdlog::info("Got {} ssl flows", tempVector.size());

    std::sort(tempVector.begin(), tempVector.end(),
        [](const AggregatedPairPointer& left, const AggregatedPairPointer& right) {
            return right.second->totalBytes[0] + right.second->totalBytes[1]
                < left.second->totalBytes[0] + left.second->totalBytes[1];
        });
    return tempVector;
}

SslStatsCollector::~SslStatsCollector()
{
    for (auto& pair : aggregatedMap) {
        delete pair.second;
    }
}
} // namespace flowstats
