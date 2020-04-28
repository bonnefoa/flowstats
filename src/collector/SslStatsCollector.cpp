#include "SslStatsCollector.hpp"
#include "SslProto.hpp"
#include <fmt/format.h>
#include <rawpdu.h>
#include <spdlog/spdlog.h>

namespace flowstats {

SslStatsCollector::SslStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration const& displayConf)
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

auto SslStatsCollector::lookupSslFlow(FlowId const& flowId) -> SslFlow&
{
    std::hash<FlowId> hash_fn;
    size_t flowHash = hash_fn(flowId);

    SslFlow& sslFlow = hashToSslFlow[flowHash];
    if (sslFlow.flowId.ports[0] == 0) {
        spdlog::debug("Create ssl flow {}", flowId.toString());
        sslFlow.flowId = flowId;
        std::optional<std::string> fqdn = getFlowFqdn(conf, sslFlow.getSrvIpInt());
        if (!fqdn.has_value()) {
            return sslFlow;
        }
        sslFlow.aggregatedFlows = lookupAggregatedFlows(sslFlow, flowId, fqdn->data());
    }

    return sslFlow;
}

auto SslStatsCollector::lookupAggregatedFlows(SslFlow const& sslFlow,
    FlowId const& flowId,
    std::string const& fqdn) -> std::vector<AggregatedSslFlow*>
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

auto SslStatsCollector::processPacket(Tins::Packet const& packet) -> void
{
    timeval pktTs = packetToTimeval(packet);
    advanceTick(pktTs);
    auto pdu = packet.pdu();
    auto ip = pdu->rfind_pdu<Tins::IP>();
    auto tcp = ip.rfind_pdu<Tins::TCP>();

    auto rawData = tcp.rfind_pdu<Tins::RawPDU>();
    auto payload = rawData.payload();
    auto cursor = Cursor(payload);
    checkValidSsl(&cursor);

    FlowId flowId(ip, tcp);
    SslFlow& sslFlow = lookupSslFlow(flowId);
    sslFlow.addPacket(packet, flowId.direction);
    for (auto& subflow : sslFlow.aggregatedFlows) {
        subflow->addPacket(packet, flowId.direction);
    }

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    sslFlow.updateFlow(packet, flowId.direction, ip, tcp);
}

auto SslStatsCollector::resetMetrics() -> void
{
    const std::lock_guard<std::mutex> lock(*getDataMutex());
    for (auto& pair : aggregatedMap) {
        pair.second->resetFlow(false);
    }
}

auto SslStatsCollector::mergePercentiles() -> void
{
    for (auto& i : aggregatedMap) {
        i.second->connections.merge();
    }
}

auto SslStatsCollector::getAggregatedPairs() const -> std::vector<AggregatedPairPointer>
{
    std::vector<AggregatedPairPointer> tempVector;

    for (auto& pair : aggregatedMap) {
        pair.second->connections.merge();
        tempVector.emplace_back(pair.first, pair.second);
    }

    spdlog::info("Got {} ssl flows", tempVector.size());

    std::sort(tempVector.begin(), tempVector.end(),
        [](AggregatedPairPointer const& left, AggregatedPairPointer const& right) {
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
    delete totalFlow;
}
} // namespace flowstats
