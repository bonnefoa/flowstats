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
    updateDisplayType(0);
};

auto SslStatsCollector::lookupSslFlow(FlowId const& flowId) -> SslFlow&
{
    std::hash<FlowId> hash_fn;
    size_t flowHash = hash_fn(flowId);

    SslFlow& sslFlow = hashToSslFlow[flowHash];
    if (sslFlow.getPort(0) == 0) {
        spdlog::debug("Create ssl flow {}", flowId.toString());
        sslFlow.setFlowId(flowId);
        std::optional<std::string> fqdn = ipToFqdn->getFlowFqdn(sslFlow.getSrvIpInt());
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
    if (getFlowstatsConfiguration().getPerIpAggr()) {
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
    auto const* pdu = packet.pdu();
    auto ip = pdu->rfind_pdu<Tins::IP>();
    auto tcp = ip.rfind_pdu<Tins::TCP>();

    auto rawData = tcp.rfind_pdu<Tins::RawPDU>();
    auto payload = rawData.payload();
    auto cursor = Cursor(payload);
    checkValidSsl(&cursor);

    FlowId flowId(ip, tcp);
    SslFlow& sslFlow = lookupSslFlow(flowId);
    auto direction = flowId.getDirection();
    sslFlow.addPacket(packet, direction);
    for (auto& subflow : sslFlow.aggregatedFlows) {
        subflow->addPacket(packet, direction);
    }

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    sslFlow.updateFlow(packet, direction, ip, tcp);
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

auto SslStatsCollector::getAggregatedPairs() const -> std::vector<AggregatedPairPointer>
{
    std::vector<AggregatedPairPointer> tempVector;

    for (auto const& pair : aggregatedMap) {
        pair.second->merge();
        tempVector.emplace_back(pair.first, pair.second);
    }

    spdlog::info("Got {} ssl flows", tempVector.size());

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
