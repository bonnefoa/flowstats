#include "TcpStatsCollector.hpp"
#include "AggregatedTcpFlow.hpp"
#include "Collector.hpp"
#include "TcpFlow.hpp"
#include <fmt/format.h>
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
        DisplayPair(DisplayResponses, { Field::SRT, Field::SRT_RATE, Field::SRT_P95, Field::SRT_P99, Field::SRT_MAX, Field::DS_P95, Field::DS_P99, Field::DS_MAX }),
        DisplayPair(DisplayTraffic, { Field::MTU, Field::PKTS, Field::PKTS_RATE, Field::BYTES, Field::BYTES_RATE }),
    });
    setTotalFlow(new AggregatedTcpFlow());
    fillSortFields();
    updateDisplayType(0);
};

auto TcpStatsCollector::detectServer(Tins::TCP const& tcp, FlowId const& flowId) -> Direction
{
    auto const flags = tcp.flags();
    auto direction = flowId.getDirection();
    if (flags & Tins::TCP::SYN) {
        if (flags & Tins::TCP::ACK) {
            auto srvPort = flowId.getPort(direction);
            srvPortsCounter[srvPort]++;
            SPDLOG_DEBUG("Incrementing port {} as server port to {}", srvPort, srvPortsCounter[srvPort]);
            return direction;
        } else {
            auto srvPort = flowId.getPort(!direction);
            srvPortsCounter[srvPort]++;
            SPDLOG_DEBUG("Incrementing port {} as server port to {}", srvPort, srvPortsCounter[srvPort]);
            return static_cast<Direction>(!direction);
        }
    }

    int firstPortCount = 0;
    int secondPortCount = 0;
    auto firstPort = flowId.getPort(direction);
    if (srvPortsCounter[firstPort] == 0) {
        firstPortCount = srvPortsCounter[firstPort];
    }
    auto secondPort = flowId.getPort(!direction);
    if (srvPortsCounter[secondPort] == 0) {
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

auto TcpStatsCollector::lookupTcpFlow(Tins::TCP const& tcp,
    FlowId const& flowId) -> TcpFlow*
{
    auto it = hashToTcpFlow.find(flowId);
    if (it != hashToTcpFlow.end()) {
        return &it->second;
    }

    auto srvDir = detectServer(tcp, flowId);
    std::optional<std::string> fqdnOpt = {};
    if (flowId.getNetwork() == +Network::IPV4) {
        auto ipSrv = flowId.getIp(srvDir);
        SPDLOG_DEBUG("Detected srvDir {}, looking for fqdn of ip {}", srvDir, ipSrv);
        fqdnOpt = ipToFqdn->getFlowFqdn(ipSrv);
    } else {
        auto ipSrv = flowId.getIpv6(srvDir);
        SPDLOG_DEBUG("Detected srvDir {}, looking for fqdn of ip {}", srvDir, ipSrv.to_string());
        fqdnOpt = ipToFqdn->getFlowFqdn(ipSrv);
    }

    if (!fqdnOpt.has_value()) {
        return nullptr;
    }

    auto const* fqdn = fqdnOpt->data();
    auto aggregatedTcpFlows = lookupAggregatedFlows(flowId, fqdn, srvDir);
    auto tcpFlow = TcpFlow(flowId, srvDir, aggregatedTcpFlows);
    SPDLOG_DEBUG("Create tcp flow {}, fqdn {}", flowId.toString(), fqdn);
    auto res = hashToTcpFlow.emplace(flowId, tcpFlow);
    return &res.first->second;
}

auto TcpStatsCollector::lookupAggregatedFlows(FlowId const& flowId,
    std::string const& fqdn,
    Direction srvDir) -> std::vector<AggregatedTcpFlow*>
{
    Tins::IPv4Address ipSrvInt = {};
    if (getFlowstatsConfiguration().getPerIpAggr()) {
        ipSrvInt = flowId.getIp(srvDir);
    }
    auto srvPort = flowId.getPort(srvDir);
    AggregatedTcpFlow* aggregatedFlow;
    // TODO Handle ipv6
    auto tcpKey = AggregatedKey(fqdn, ipSrvInt, {}, srvPort);
    const std::lock_guard<std::mutex> lock(*getDataMutex());
    auto* aggregatedMap = getAggregatedMap();
    auto it = aggregatedMap->find(tcpKey);
    if (it == aggregatedMap->end()) {
        aggregatedFlow = new AggregatedTcpFlow(flowId, fqdn, srvDir);
        aggregatedMap->emplace(tcpKey, aggregatedFlow);
        SPDLOG_DEBUG("Create aggregated tcp flow for {}", flowId.toString());
    } else {
        aggregatedFlow = dynamic_cast<AggregatedTcpFlow*>(it->second);
    }
    std::vector<AggregatedTcpFlow*> aggregatedFlows;
    aggregatedFlows.push_back(aggregatedFlow);
    return aggregatedFlows;
}

auto TcpStatsCollector::processPacket(Tins::Packet const& packet,
    FlowId const& flowId,
    Tins::IP const* ip,
    Tins::IPv6 const* ipv6,
    Tins::TCP const* tcp,
    Tins::UDP const*) -> void
{
    if (tcp == nullptr) {
        return;
    }

    auto* tcpFlow = lookupTcpFlow(*tcp, flowId);
    if (tcpFlow == nullptr) {
        return;
    }

    auto direction = flowId.getDirection();
    tcpFlow->addPacket(packet, direction);

    for (auto* subflow : tcpFlow->getAggregatedFlows()) {
        subflow->addPacket(packet, direction);
        subflow->updateFlow(packet, flowId, *tcp);
    }

    tcpFlow->updateFlow(packet, direction, ip, ipv6, *tcp);
}

auto TcpStatsCollector::advanceTick(timeval now) -> void
{
    if (now.tv_sec <= lastTick) {
        return;
    }
    std::vector<FlowId> toTimeout;
    lastTick = now.tv_sec;
    SPDLOG_DEBUG("Advance tick to {}", now.tv_sec);
    for (auto it : hashToTcpFlow) {
        TcpFlow& flow = it.second;
        auto lastPacketTime = flow.getLastPacketTime();
        SPDLOG_DEBUG("Check flow {} for timeouts, now {}, lastPacketTime {} {}",
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
        SPDLOG_DEBUG("flow.{}, maxDelta: {}", flow.getFlowId().toString(), maxDelta);
        auto timeoutFlow = getFlowstatsConfiguration().getTimeoutFlow();
        if (maxDelta > timeoutFlow) {
            SPDLOG_DEBUG("Timeout flow {}, now {}, maxDelta {} > {}",
                flow.getFlowId().toString(), now.tv_sec, maxDelta, timeoutFlow);
            toTimeout.push_back(it.first);
            flow.timeoutFlow();
        }
    }
    for (auto i : toTimeout) {
        hashToTcpFlow.erase(i);
    }
}

auto TcpStatsCollector::getSortFun(Field field) const -> sortFlowFun
{
    auto sortFun = Collector::getSortFun(field);
    if (sortFun != nullptr) {
        return sortFun;
    }
    switch (field) {
    case Field::SRT:
        return &AggregatedTcpFlow::sortBySrt;
    case Field::SRT_RATE:
        return &AggregatedTcpFlow::sortBySrtRate;
    case Field::REQ:
        return &AggregatedTcpFlow::sortByRequest;
    case Field::REQ_RATE:
        return &AggregatedTcpFlow::sortByRequestRate;
    case Field::SYN:
        return &AggregatedTcpFlow::sortBySyn;
    case Field::SYNACK:
        return &AggregatedTcpFlow::sortBySynAck;
    case Field::ZWIN:
        return &AggregatedTcpFlow::sortByZwin;
    case Field::RST:
        return &AggregatedTcpFlow::sortByRst;
    case Field::FIN:
        return &AggregatedTcpFlow::sortByFin;
    case Field::ACTIVE_CONNECTIONS:
        return &AggregatedTcpFlow::sortByActiveConnections;
    case Field::FAILED_CONNECTIONS:
        return &AggregatedTcpFlow::sortByFailedConnections;
    case Field::CONN:
        return &AggregatedTcpFlow::sortByConnections;
    case Field::CONN_RATE:
        return &AggregatedTcpFlow::sortByConnectionRate;
    case Field::CLOSE:
        return &AggregatedTcpFlow::sortByClose;
    case Field::CLOSE_RATE:
        return &AggregatedTcpFlow::sortByCloseRate;

    case Field::MTU:
        return &AggregatedTcpFlow::sortByMtu;

    case Field::CT_P95:
        return &AggregatedTcpFlow::sortByCtP95;
    case Field::CT_P99:
        return &AggregatedTcpFlow::sortByCtP99;

    case Field::SRT_P95:
        return &AggregatedTcpFlow::sortBySrtP95;
    case Field::SRT_P99:
        return &AggregatedTcpFlow::sortBySrtP99;
    case Field::SRT_MAX:
        return &AggregatedTcpFlow::sortBySrtMax;

    case Field::DS_P95:
        return &AggregatedTcpFlow::sortByDsP95;
    case Field::DS_P99:
        return &AggregatedTcpFlow::sortByDsP99;
    case Field::DS_MAX:
        return &AggregatedTcpFlow::sortByDsMax;
    default:
        return nullptr;
    }
}

} // namespace flowstats
