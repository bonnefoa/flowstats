#include "TcpStatsCollector.hpp"
#include "TcpAggregatedFlow.hpp"
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
    auto& flowFormatter = getFlowFormatter();
    if (conf.getPerIpAggr()) {
        flowFormatter.setDisplayKeys({ Field::FQDN, Field::IP, Field::PORT, Field::DIR });
    } else {
        flowFormatter.setDisplayKeys({ Field::FQDN, Field::PORT, Field::DIR });
    }

    setDisplayPairs({
        DisplayFieldValues(DisplayTcpFlags, { Field::SYN, Field::SYN_RATE, Field::SYNACK, Field::SYNACK_RATE, Field::FIN, Field::FIN_RATE }),
        DisplayFieldValues(DisplayOtherFlags, { Field::RST, Field::RST_RATE, Field::ZWIN, Field::ZWIN_RATE }),
        DisplayFieldValues(DisplayConnections, { Field::ACTIVE_CONNECTIONS, Field::FAILED_CONNECTIONS, Field::CONN, Field::CONN_RATE, Field::CLOSE, Field::CLOSE_RATE }),
        DisplayFieldValues(DisplayConnectionTimes, { Field::CT_P95, Field::CT_TOTAL_P95, Field::CT_P99, Field::CT_TOTAL_P99 }),
        DisplayFieldValues(DisplayResponses, { Field::SRT, Field::SRT_RATE, Field::SRT_P95, Field::SRT_TOTAL_P95, Field::SRT_P99, Field::SRT_TOTAL_P99 }),
        DisplayFieldValues(DisplayClients, { Field::TOP_CLIENT_IPS_IP, Field::TOP_CLIENT_IPS_PKTS, Field::TOP_CLIENT_IPS_BYTES }, true),
        DisplayFieldValues(DisplayTraffic, { Field::MTU, Field::PKTS, Field::PKTS_RATE, Field::BYTES, Field::BYTES_RATE }),
    });
    setTotalFlow(new TcpAggregatedFlow());
    updateDisplayType(0);
    fillSortFields();
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
    auto ipSrv = flowId.getIp(srvDir);
    SPDLOG_DEBUG("Detected srvDir {}, looking for fqdn of ip {}", srvDir, ipSrv.getAddrStr());
    fqdnOpt = ipToFqdn->getFlowFqdn(ipSrv);

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
    Direction srvDir) -> std::vector<TcpAggregatedFlow*>
{
    IPAddress ipSrvInt = {};
    if (getFlowstatsConfiguration().getPerIpAggr()) {
        ipSrvInt = flowId.getIp(srvDir);
    }
    auto srvPort = flowId.getPort(srvDir);
    TcpAggregatedFlow* aggregatedFlow;
    auto tcpKey = AggregatedKey(fqdn, ipSrvInt, srvPort);
    const std::lock_guard<std::mutex> lock(*getDataMutex());
    auto* aggregatedMap = getAggregatedMap();
    auto it = aggregatedMap->find(tcpKey);
    if (it == aggregatedMap->end()) {
        aggregatedFlow = new TcpAggregatedFlow(flowId, fqdn, srvDir);
        aggregatedMap->emplace(tcpKey, aggregatedFlow);
        SPDLOG_DEBUG("Create aggregated tcp flow for {}", flowId.toString());
    } else {
        aggregatedFlow = dynamic_cast<TcpAggregatedFlow*>(it->second);
    }
    std::vector<TcpAggregatedFlow*> aggregatedFlows;
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

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    auto direction = flowId.getDirection();
    tcpFlow->addPacket(packet, direction);

    for (auto* subflow : tcpFlow->getTcpAggregatedFlows()) {
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
    for (auto& i : toTimeout) {
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
            return &TcpAggregatedFlow::sortBySrt;
        case Field::SRT_RATE:
            return &TcpAggregatedFlow::sortBySrtRate;
        case Field::REQ:
            return &TcpAggregatedFlow::sortByRequest;
        case Field::REQ_RATE:
            return &TcpAggregatedFlow::sortByRequestRate;
        case Field::SYN:
            return &TcpAggregatedFlow::sortBySyn;
        case Field::SYN_RATE:
            return &TcpAggregatedFlow::sortBySynRate;
        case Field::SYNACK:
            return &TcpAggregatedFlow::sortBySynAck;
        case Field::SYNACK_RATE:
            return &TcpAggregatedFlow::sortBySynAckRate;
        case Field::ZWIN:
            return &TcpAggregatedFlow::sortByZwin;
        case Field::ZWIN_RATE:
            return &TcpAggregatedFlow::sortByZwinRate;
        case Field::RST:
            return &TcpAggregatedFlow::sortByRst;
        case Field::RST_RATE:
            return &TcpAggregatedFlow::sortByRstRate;
        case Field::FIN:
            return &TcpAggregatedFlow::sortByFin;
        case Field::FIN_RATE:
            return &TcpAggregatedFlow::sortByFinRate;
        case Field::ACTIVE_CONNECTIONS:
            return &TcpAggregatedFlow::sortByActiveConnections;
        case Field::FAILED_CONNECTIONS:
            return &TcpAggregatedFlow::sortByFailedConnections;
        case Field::CONN:
            return &TcpAggregatedFlow::sortByConnections;
        case Field::CONN_RATE:
            return &TcpAggregatedFlow::sortByConnectionRate;
        case Field::CLOSE:
            return &TcpAggregatedFlow::sortByClose;
        case Field::CLOSE_RATE:
            return &TcpAggregatedFlow::sortByCloseRate;

        case Field::MTU:
            return &TcpAggregatedFlow::sortByMtu;

        case Field::CT_P95:
            return &TcpAggregatedFlow::sortByCtP95;
        case Field::CT_TOTAL_P95:
            return &TcpAggregatedFlow::sortByCtTotalP95;
        case Field::CT_P99:
            return &TcpAggregatedFlow::sortByCtP99;
        case Field::CT_TOTAL_P99:
            return &TcpAggregatedFlow::sortByCtTotalP99;

        case Field::SRT_P95:
            return &TcpAggregatedFlow::sortBySrtP95;
        case Field::SRT_TOTAL_P95:
            return &TcpAggregatedFlow::sortBySrtTotalP95;
        case Field::SRT_P99:
            return &TcpAggregatedFlow::sortBySrtP99;
        case Field::SRT_TOTAL_P99:
            return &TcpAggregatedFlow::sortBySrtTotalP99;
        case Field::SRT_MAX:
            return &TcpAggregatedFlow::sortBySrtMax;
        case Field::SRT_TOTAL_MAX:
            return &TcpAggregatedFlow::sortBySrtTotalMax;

        case Field::DS_P95:
            return &TcpAggregatedFlow::sortByDsP95;
        case Field::DS_TOTAL_P95:
            return &TcpAggregatedFlow::sortByDsTotalP95;
        case Field::DS_P99:
            return &TcpAggregatedFlow::sortByDsP99;
        case Field::DS_TOTAL_P99:
            return &TcpAggregatedFlow::sortByDsTotalP99;
        case Field::DS_MAX:
            return &TcpAggregatedFlow::sortByDsMax;
        case Field::DS_TOTAL_MAX:
            return &TcpAggregatedFlow::sortByDsTotalMax;
        default:
            return nullptr;
    }
}

} // namespace flowstats
