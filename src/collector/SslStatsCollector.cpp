#include "SslStatsCollector.hpp"
#include "SslProto.hpp"
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <tins/rawpdu.h>

namespace flowstats {

SslStatsCollector::SslStatsCollector(FlowstatsConfiguration const& conf, DisplayConfiguration const& displayConf, IpToFqdn* ipToFqdn)
    : Collector { conf, displayConf }
    , ipToFqdn(ipToFqdn)
{
    if (conf.getPerIpAggr()) {
        setDisplayKeys({ Field::FQDN, Field::IP, Field::PORT, Field::DIR });
    } else {
        setDisplayKeys({ Field::FQDN, Field::PORT, Field::DIR });
    }

    setDisplayPairs({
        DisplayPair(DisplayConnections, { Field::CONN, Field::CONN_RATE, Field::CT_P95, Field::CT_P99 }),
        DisplayPair(DisplayTraffic, { Field::PKTS, Field::PKTS_RATE, Field::BYTES, Field::BYTES_RATE }),
    });
    setTotalFlow(new AggregatedSslFlow());
    fillSortFields();
    updateDisplayType(0);
};

auto SslStatsCollector::lookupSslFlow(FlowId const& flowId) -> SslFlow*
{
    std::hash<FlowId> hash_fn;
    auto flowHash = hash_fn(flowId);

    auto it = hashToSslFlow.find(flowHash);
    if (it != hashToSslFlow.end()) {
        return &it->second;
    }

    auto fqdnOpt = ipToFqdn->getFlowFqdn(flowId.getIp(!flowId.getDirection()));
    if (!fqdnOpt.has_value()) {
        return nullptr;
    }

    auto fqdn = fqdnOpt->data();
    // TODO dectect server port
    auto aggregatedFlows = lookupAggregatedFlows(flowId, fqdn, FROM_SERVER);
    spdlog::debug("Create ssl flow {}", flowId.toString());
    auto sslFlow = SslFlow(flowId, fqdn, aggregatedFlows);
    auto res = hashToSslFlow.insert({ flowHash, sslFlow });
    return &res.first->second;
}

auto SslStatsCollector::lookupAggregatedFlows(FlowId const& flowId, std::string const& fqdn, Direction srvDir) -> std::vector<AggregatedSslFlow*>
{
    std::vector<AggregatedSslFlow*> subflows;
    IPv4 ipSrvInt = 0;
    if (getFlowstatsConfiguration().getPerIpAggr()) {
        ipSrvInt = flowId.getIp(srvDir);
    }
    AggregatedTcpKey tcpKey = AggregatedTcpKey(fqdn, ipSrvInt, flowId.getPort(srvDir));
    AggregatedSslFlow* aggregatedFlow;

    auto it = aggregatedMap.find(tcpKey);
    if (it == aggregatedMap.end()) {
        aggregatedFlow = new AggregatedSslFlow(flowId, fqdn);
        aggregatedMap.insert({ tcpKey, aggregatedFlow });
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
    auto const* pdu = packet.pdu();
    auto ip = pdu->rfind_pdu<Tins::IP>();
    auto tcp = ip.rfind_pdu<Tins::TCP>();

    auto rawData = tcp.rfind_pdu<Tins::RawPDU>();
    auto payload = rawData.payload();
    auto cursor = Cursor(payload);
    checkValidSsl(&cursor);

    FlowId flowId(ip, tcp);
    auto sslFlow = lookupSslFlow(flowId);
    if (sslFlow == nullptr) {
        return;
    }
    auto direction = flowId.getDirection();
    sslFlow->addPacket(packet, direction);

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    sslFlow->updateFlow(packet, direction, tcp);
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
        i.second->merge();
    }
}

typedef bool (AggregatedSslFlow::*sortFlowFun)(AggregatedSslFlow const&) const;
auto sortAggregatedSsl(sortFlowFun sortFlow,
    AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    auto* rightSsl = dynamic_cast<AggregatedSslFlow*>(right.second);
    auto* leftSsl = dynamic_cast<AggregatedSslFlow*>(left.second);
    if (rightSsl == nullptr || leftSsl == nullptr) {
        return false;
    }
    return (rightSsl->*sortFlow)(*leftSsl);
}

auto SslStatsCollector::getAggregatedPairs() const -> std::vector<AggregatedPairPointer>
{
    std::vector<AggregatedPairPointer> tempVector;

    for (auto const& pair : aggregatedMap) {
        pair.second->merge();
        tempVector.emplace_back(pair.first, pair.second);
    }

    spdlog::info("Got {} ssl flows", tempVector.size());

    auto sortFunc = sortAggregatedPairByFqdn;
    switch (getDisplayConf().sslSelectedField) {
    case Field::FQDN:
        sortFunc = sortAggregatedPairByFqdn;
        break;
    case Field::BYTES:
        sortFunc = sortAggregatedPairByByte;
        break;
    case Field::PKTS:
        sortFunc = sortAggregatedPairByPacket;
        break;
    default:
        break;
    }

    std::sort(tempVector.begin(), tempVector.end(),
        [](AggregatedPairPointer const& left, AggregatedPairPointer const& right) {
            return right.second < left.second;
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
