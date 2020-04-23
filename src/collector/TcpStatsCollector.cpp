#include "TcpStatsCollector.hpp"
#include "AggregatedTcpFlow.hpp"
#include "Collector.hpp"
#include "TcpFlow.hpp"
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <string>

namespace flowstats {

TcpStatsCollector::TcpStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration& displayConf)
    : Collector { conf, displayConf }
{
    if (conf.perIpAggr) {
        flowFormatter.setDisplayKeys({ "fqdn", "ip", "port", "dir" });
    } else {
        flowFormatter.setDisplayKeys({ "fqdn", "port", "dir" });
    }

    displayPairs = {
        DisplayPair(DisplayFlags, { "syn", "synack", "fin", "rst", "zwin" }),
        DisplayPair(DisplayConnections, { "active_connections", "failed_connections", "conn", "conn_s", "ctp95", "ctp99", "close", "close_s" }),
        DisplayPair(DisplayResponses, { "srt", "srt_s", "srt95", "srt99", "srtMax", "ds95", "ds99", "dsMax" }),
        DisplayPair(DisplayTraffic, { "mtu", "pkts", "pkts_s", "bytes", "bytes_s" }),
    };
    totalFlow = new AggregatedTcpFlow();
    updateDisplayType(0);
};

auto TcpStatsCollector::lookupTcpFlow(
    Tins::IP* ip,
    Tins::TCP* tcp,
    FlowId& flowId) -> TcpFlow&
{
    std::hash<FlowId> hash_fn;
    size_t flowHash = hash_fn(flowId);
    TcpFlow& tcpFlow = hashToTcpFlow[flowHash];
    if (tcpFlow.flowHash == 0) {
        tcpFlow = TcpFlow(ip, tcp, flowHash);
        tcpFlow.detectServer(tcp, flowId.direction, srvPortsCounter);
        std::optional<std::string> fqdn = getFlowFqdn(conf, tcpFlow.getSrvIp());
        if (!fqdn.has_value()) {
            return tcpFlow;
        }
        spdlog::debug("Create tcp flow {}, flowhash {}, fqdn {}", flowId.toString(), tcpFlow.flowHash, fqdn->data());
        tcpFlow.fqdn = fqdn->data();
        tcpFlow.aggregatedFlows = lookupAggregatedFlows(tcpFlow, flowId);
    }
    return tcpFlow;
}

auto TcpStatsCollector::lookupAggregatedFlows(TcpFlow& tcpFlow, FlowId& flowId) -> std::vector<AggregatedTcpFlow*>
{
    IPv4 ipSrvInt = 0;
    if (conf.perIpAggr) {
        ipSrvInt = tcpFlow.getSrvIpInt();
    }
    AggregatedTcpFlow* aggregatedFlow;
    AggregatedTcpKey tcpKey = AggregatedTcpKey(tcpFlow.fqdn, ipSrvInt,
        tcpFlow.getSrvPort());
    const std::lock_guard<std::mutex> lock(*getDataMutex());
    auto it = aggregatedMap.find(tcpKey);
    if (it == aggregatedMap.end()) {
        aggregatedFlow = new AggregatedTcpFlow(flowId, tcpFlow.fqdn);
        aggregatedFlow->srvPos = tcpFlow.srvPos;
        aggregatedMap[tcpKey] = aggregatedFlow;
        spdlog::debug("Create aggregated tcp flow for {}", tcpKey.toString());
    } else {
        aggregatedFlow = it->second;
    }
    std::vector<AggregatedTcpFlow*> aggregatedFlows;
    aggregatedFlows.push_back(aggregatedFlow);
    return aggregatedFlows;
}

void TcpStatsCollector::processPacket(Tins::Packet& packet)
{
    advanceTick(packetToTimeval(packet));
    auto pdu = packet.pdu();
    auto ip = pdu->find_pdu<Tins::IP>();
    auto tcp = ip->find_pdu<Tins::TCP>();
    if (tcp == nullptr) {
        return;
    }
    FlowId flowId(ip, tcp);

    TcpFlow& tcpFlow = lookupTcpFlow(ip, tcp, flowId);
    if (tcpFlow.fqdn == "") {
        return;
    }

    tcpFlow.addPacket(packet, flowId.direction);

    for (auto& subflow : tcpFlow.aggregatedFlows) {
        subflow->addPacket(packet, flowId.direction);
        subflow->updateFlow(packet, flowId, ip, tcp);
    }

    tcpFlow.updateFlow(packet, flowId.direction, ip, tcp);

    if (tcp->has_flags(Tins::TCP::SYN) && tcpFlow.opening == false) {
        tcpFlow.opening = true;
    }
}

void TcpStatsCollector::advanceTick(timeval now)
{
    if (now.tv_sec <= lastTick) {
        return;
    }
    std::vector<size_t> toTimeout;
    lastTick = now.tv_sec;
    spdlog::debug("Advance tick to {}", now.tv_sec);
    for (auto it = hashToTcpFlow.begin(); it != hashToTcpFlow.end(); it++) {
        TcpFlow& flow = it->second;
        spdlog::debug("Check flow {} for timeouts, now {}, lastPacketTime {} {}",
            flow.flowId.toString(), now.tv_sec,
            flow.lastPacketTime[0].tv_sec, flow.lastPacketTime[1].tv_sec);
        if (flow.lastPacketTime[FROM_CLIENT].tv_sec == 0
            && flow.lastPacketTime[FROM_SERVER].tv_sec == 0) {
            continue;
        }
        uint32_t deltas[2] = { 0, 0 };
        for (int i = 0; i < 2; ++i) {
            if (flow.lastPacketTime[i].tv_sec > 0) {
                deltas[i] = getTimevalDeltaS(flow.lastPacketTime[i], now);
            }
        }
        uint32_t maxDelta = std::max(deltas[0], deltas[1]);
        spdlog::debug("flow.{}, maxDelta: {}", flow.flowId.toString(), maxDelta);
        if (maxDelta > conf.timeoutFlow) {
            spdlog::debug("Timeout flow {}, now {}, maxDelta {} > {}",
                flow.flowId.toString(), now.tv_sec, maxDelta, conf.timeoutFlow);
            toTimeout.push_back(it->first);
            flow.timeoutFlow();
        }
    }
    for (auto i : toTimeout) {
        assert(hashToTcpFlow.erase(i));
    }
}

void TcpStatsCollector::resetMetrics()
{
    const std::lock_guard<std::mutex> lock(*getDataMutex());
    for (auto& pair : aggregatedMap) {
        pair.second->resetFlow(false);
    }
}

auto TcpStatsCollector::getMetrics() -> std::vector<std::string>
{
    std::vector<std::string> lst;
    for (auto& pair : aggregatedMap) {
        struct AggregatedTcpFlow* val = pair.second;
        DogFood::Tags tags = DogFood::Tags({ { "fqdn", val->fqdn },
            { "ip", val->getSrvIp().to_string() },
            { "port", std::to_string(val->getSrvPort()) } });
        for (auto& i : val->srts.getPoints()) {
            lst.push_back(DogFood::Metric("flowstats.tcp.srt", i,
                DogFood::Histogram, 1, tags));
        }
        for (auto& i : val->connections.getPoints()) {
            lst.push_back(DogFood::Metric("flowstats.tcp.ct", i,
                DogFood::Histogram, 1, tags));
        }
        if (val->activeConnections) {
            lst.push_back(DogFood::Metric("flowstats.tcp.activeConnections", val->activeConnections, DogFood::Counter, 1, tags));
        }
        if (val->failedConnections) {
            lst.push_back(DogFood::Metric("flowstats.tcp.failedConnections", val->failedConnections,
                DogFood::Counter, 1, tags));
        }
    }
    return lst;
}

void TcpStatsCollector::mergePercentiles()
{
    for (auto& i : aggregatedMap) {
        i.second->srts.merge();
        i.second->connections.merge();
        i.second->requestSizes.merge();
    }
}

auto sortAggregatedTcpBySrt(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    auto* rightTcp = dynamic_cast<AggregatedTcpFlow*>(right.second);
    auto* leftTcp = dynamic_cast<AggregatedTcpFlow*>(left.second);
    return rightTcp->srts.getPercentile(1.0) < leftTcp->srts.getPercentile(1.0);
}

auto sortAggregatedTcpByRequest(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    auto* rightTcp = dynamic_cast<AggregatedTcpFlow*>(right.second);
    auto* leftTcp = dynamic_cast<AggregatedTcpFlow*>(left.second);
    return rightTcp->totalSrts < leftTcp->totalSrts;
}

auto sortAggregatedTcpByRequestRate(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    auto* rightTcp = dynamic_cast<AggregatedTcpFlow*>(right.second);
    auto* leftTcp = dynamic_cast<AggregatedTcpFlow*>(left.second);
    return rightTcp->srts.getCount() < leftTcp->srts.getCount();
}

auto TcpStatsCollector::getAggregatedPairs() -> std::vector<AggregatedPairPointer>
{
    std::vector<AggregatedPairPointer> tempVector = std::vector<AggregatedPairPointer>(aggregatedMap.begin(), aggregatedMap.end());
    spdlog::info("Got {} tcp flows", tempVector.size());

    auto sortFunc = sortAggregatedPairByByte;
    switch (displayConf.sortType) {
    case SortFqdn:
        sortFunc = sortAggregatedPairByFqdn;
        break;
    case SortByte:
        sortFunc = sortAggregatedPairByByte;
        break;
    case SortPacket:
        sortFunc = sortAggregatedPairByPacket;
        break;
    case SortRequestRate:
        sortFunc = sortAggregatedTcpByRequestRate;
        break;
    case SortRequest:
        sortFunc = sortAggregatedTcpByRequest;
        break;
    case SortSrt:
        sortFunc = sortAggregatedTcpBySrt;
        break;
    }
    std::sort(tempVector.begin(), tempVector.end(), sortFunc);
    return tempVector;
}

TcpStatsCollector::~TcpStatsCollector()
{
    for (auto& pair : aggregatedMap) {
        delete pair.second;
    }
}
} // namespace flowstats
