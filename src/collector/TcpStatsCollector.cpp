#include "TcpStatsCollector.hpp"
#include "AggregatedTcpFlow.hpp"
#include "Collector.hpp"
#include "TcpFlow.hpp"
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <string>

namespace flowstats {

TcpStatsCollector::TcpStatsCollector(FlowstatsConfiguration const& conf,
    DisplayConfiguration const& displayConf,
    IpToFqdn* ipToFqdn)
    : Collector { conf, displayConf }
    , ipToFqdn(ipToFqdn)
{
    if (conf.getPerIpAggr()) {
        setDisplayKeys({ Field::FQDN, Field::IP, Field::PORT, Field::DIR });
    } else {
        setDisplayKeys({ Field::FQDN, Field::PORT, Field::DIR });
    }

    setDisplayPairs({
        DisplayPair(DisplayFlags, { Field::SYN, Field::SYNACK, Field::FIN, Field::RST, Field::ZWIN }),
        DisplayPair(DisplayConnections, { Field::ACTIVE_CONNECTIONS, Field::FAILED_CONNECTIONS, Field::CONN, Field::CONN_RATE, Field::CT_P95, Field::CT_P99, Field::CLOSE, Field::CLOSE_RATE }),
        DisplayPair(DisplayResponses, { Field::SRT, Field::SRT_RATE, Field::SRT_P95, Field::SRT_P99, Field::SRTMAX, Field::DS_P95, Field::DS_P99, Field::DSMAX }),
        DisplayPair(DisplayTraffic, { Field::MTU, Field::PKTS, Field::PKTS_RATE, Field::BYTES, Field::BYTES_RATE }),
    });
    setTotalFlow(new AggregatedTcpFlow());
    fillSortFields();
    updateDisplayType(0);
};

auto TcpStatsCollector::detectServer(Tins::TCP const& tcp, FlowId const& flowId, std::map<uint16_t, int>& srvPortsCounter) -> Direction
{
    auto const flags = tcp.flags();
    auto direction = flowId.getDirection();
    if (flags & Tins::TCP::SYN) {
        if (flags & Tins::TCP::ACK) {
            auto srvPort = flowId.getPort(direction);
            srvPortsCounter[srvPort]++;
            spdlog::debug("Incrementing port {} as server port to {}", srvPort, srvPortsCounter[srvPort]);
            return direction;
        } else {
            auto srvPort = flowId.getPort(!direction);
            srvPortsCounter[srvPort]++;
            spdlog::debug("Incrementing port {} as server port to {}", srvPort, srvPortsCounter[srvPort]);
            return static_cast<Direction>(!direction);
        }
    }

    int firstPortCount = 0;
    int secondPortCount = 0;
    auto firstPort = flowId.getPort(direction);
    if (srvPortsCounter.find(firstPort) != srvPortsCounter.end()) {
        firstPortCount = srvPortsCounter[firstPort];
    }
    auto secondPort = flowId.getPort(!direction);
    if (srvPortsCounter.find(secondPort) != srvPortsCounter.end()) {
        secondPortCount = srvPortsCounter[secondPort];
    }
    if (firstPortCount > secondPortCount) {
        return direction;
    }
    if (firstPort < secondPort) {
        return direction;
    }
    return static_cast<Direction>(!direction);
}

auto TcpStatsCollector::lookupTcpFlow(
    Tins::IP const& ip,
    Tins::TCP const& tcp,
    FlowId const& flowId) -> TcpFlow*
{
    std::hash<FlowId> hash_fn;
    size_t flowHash = hash_fn(flowId);
    auto it = hashToTcpFlow.find(flowHash);
    if (it != hashToTcpFlow.end()) {
        return &it->second;
    }

    auto srvDir = detectServer(tcp, flowId, srvPortsCounter);
    auto ipSrv = flowId.getIp(srvDir);
    spdlog::debug("Detected srvDir {}, looking for fqdn of ip {}", srvDir, ipSrv);
    std::optional<std::string> fqdnOpt = ipToFqdn->getFlowFqdn(ipSrv);
    if (!fqdnOpt.has_value()) {
        return nullptr;
    }

    auto fqdn = fqdnOpt->data();
    auto aggregatedTcpFlows = lookupAggregatedFlows(flowId, fqdn, srvDir);
    auto tcpFlow = TcpFlow(ip, tcp, srvDir, aggregatedTcpFlows);
    spdlog::debug("Create tcp flow {}, flowhash {}, fqdn {}", flowId.toString(), flowHash, fqdn);
    auto res = hashToTcpFlow.emplace(flowHash, tcpFlow);
    return &res.first->second;
}

auto TcpStatsCollector::lookupAggregatedFlows(FlowId const& flowId, std::string const& fqdn, Direction srvDir) -> std::vector<AggregatedTcpFlow*>
{
    auto ipSrvInt = 0;
    if (getFlowstatsConfiguration().getPerIpAggr()) {
        ipSrvInt = flowId.getIp(srvDir);
    }
    auto srvPort = flowId.getPort(srvDir);
    AggregatedTcpFlow* aggregatedFlow;
    AggregatedTcpKey tcpKey = AggregatedTcpKey(fqdn, ipSrvInt,
        srvPort);
    const std::lock_guard<std::mutex> lock(*getDataMutex());
    auto* aggregatedMap = getAggregatedMap();
    auto it = aggregatedMap->find(tcpKey);
    if (it == aggregatedMap->end()) {
        auto aggregatedObj = new AggregatedTcpFlow(flowId, fqdn, srvDir);
        auto it = aggregatedMap->emplace(tcpKey, aggregatedObj);
        aggregatedFlow = static_cast<AggregatedTcpFlow*>(it.first->second);
        spdlog::debug("Create aggregated tcp flow for {}", tcpKey.toString());
    } else {
        aggregatedFlow = static_cast<AggregatedTcpFlow*>(it->second);
    }
    std::vector<AggregatedTcpFlow*> aggregatedFlows;
    aggregatedFlows.push_back(aggregatedFlow);
    return aggregatedFlows;
}

auto TcpStatsCollector::processPacket(Tins::Packet const& packet) -> void
{
    advanceTick(packetToTimeval(packet));
    auto const* pdu = packet.pdu();
    auto ip = pdu->rfind_pdu<Tins::IP>();
    auto tcp = ip.rfind_pdu<Tins::TCP>();
    FlowId flowId(ip, tcp);

    auto tcpFlow = lookupTcpFlow(ip, tcp, flowId);
    if (tcpFlow == nullptr) {
        return;
    }

    auto direction = flowId.getDirection();
    tcpFlow->addPacket(packet, direction);

    for (auto& subflow : tcpFlow->getAggregatedFlows()) {
        subflow->addPacket(packet, direction);
        subflow->updateFlow(packet, flowId, tcp);
    }

    tcpFlow->updateFlow(packet, direction, ip, tcp);
}

auto TcpStatsCollector::advanceTick(timeval now) -> void
{
    if (now.tv_sec <= lastTick) {
        return;
    }
    std::vector<size_t> toTimeout;
    lastTick = now.tv_sec;
    spdlog::debug("Advance tick to {}", now.tv_sec);
    for (auto it : hashToTcpFlow) {
        TcpFlow& flow = it.second;
        auto lastPacketTime = flow.getLastPacketTime();
        spdlog::debug("Check flow {} for timeouts, now {}, lastPacketTime {} {}",
            flow.getFlowId().toString(), now.tv_sec,
            lastPacketTime[0].tv_sec, lastPacketTime[1].tv_sec);
        if (lastPacketTime[FROM_CLIENT].tv_sec == 0
            && lastPacketTime[FROM_SERVER].tv_sec == 0) {
            continue;
        }
        std::array<uint32_t, 2> deltas = { 0, 0 };
        for (int i = 0; i < 2; ++i) {
            if (lastPacketTime[i].tv_sec > 0) {
                deltas[i] = getTimevalDeltaS(lastPacketTime[i], now);
            }
        }
        uint32_t maxDelta = std::max(deltas[0], deltas[1]);
        spdlog::debug("flow.{}, maxDelta: {}", flow.getFlowId().toString(), maxDelta);
        auto timeoutFlow = getFlowstatsConfiguration().getTimeoutFlow();
        if (maxDelta > timeoutFlow) {
            spdlog::debug("Timeout flow {}, now {}, maxDelta {} > {}",
                flow.getFlowId().toString(), now.tv_sec, maxDelta, timeoutFlow);
            toTimeout.push_back(it.first);
            flow.timeoutFlow();
        }
    }
    for (auto i : toTimeout) {
        hashToTcpFlow.erase(i);
    }
}

auto TcpStatsCollector::getSortFun(Field field) const -> Flow::sortFlowFun
{
    auto sortFun = Collector::getSortFun(field);
    if (sortFun != nullptr) {
        return sortFun;
    }
    switch (field) {
    case Field::SRT:
        return &AggregatedTcpFlow::sortBySrt;
    case Field::REQ:
        return &AggregatedTcpFlow::sortByRequest;
    case Field::REQ_RATE:
        return &AggregatedTcpFlow::sortByRequestRate;
    default:
        return nullptr;
    }
}

} // namespace flowstats
