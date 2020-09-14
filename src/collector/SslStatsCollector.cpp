#include "SslStatsCollector.hpp"
#include "SslProto.hpp"
#include <fmt/format.h>
#include <tins/rawpdu.h>

namespace flowstats {

SslStatsCollector::SslStatsCollector(FlowstatsConfiguration const& conf, DisplayConfiguration const& displayConf, IpToFqdn* ipToFqdn)
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
        DisplayPair(DisplayConnections, { Field::CONN, Field::CONN_RATE, Field::CT_P95, Field::CT_P99 }),
        DisplayPair(DisplayTraffic, { Field::PKTS, Field::PKTS_RATE, Field::PKTS_AVG, Field::BYTES, Field::BYTES_RATE, Field::BYTES_AVG }),
    });
    setTotalFlow(new AggregatedSslFlow());
    updateDisplayType(0);
    fillSortFields();
};

auto SslStatsCollector::lookupSslFlow(FlowId const& flowId) -> SslFlow*
{
    auto it = hashToSslFlow.find(flowId);
    if (it != hashToSslFlow.end()) {
        return &it->second;
    }

    auto fqdnOpt = ipToFqdn->getFlowFqdn(flowId.getIp(!flowId.getDirection()));
    if (!fqdnOpt.has_value()) {
        return nullptr;
    }

    auto const* fqdn = fqdnOpt->data();
    // TODO dectect server port
    auto aggregatedFlows = lookupAggregatedFlows(flowId, fqdn, FROM_SERVER);
    SPDLOG_DEBUG("Create ssl flow {}", flowId.toString());
    auto sslFlow = SslFlow(flowId, fqdn, aggregatedFlows);
    auto res = hashToSslFlow.insert({ flowId, sslFlow });
    return &res.first->second;
}

auto SslStatsCollector::lookupAggregatedFlows(FlowId const& flowId, std::string const& fqdn, Direction srvDir) -> std::vector<AggregatedSslFlow*>
{
    std::vector<AggregatedSslFlow*> subflows;
    IPv4 ipSrvInt = 0;
    if (getFlowstatsConfiguration().getPerIpAggr()) {
        ipSrvInt = flowId.getIp(srvDir);
    }
    auto tcpKey = AggregatedKey(fqdn, ipSrvInt, {}, flowId.getPort(srvDir));
    AggregatedSslFlow* aggregatedFlow;

    auto* aggregatedMap = getAggregatedMap();
    auto it = aggregatedMap->find(tcpKey);
    if (it == aggregatedMap->end()) {
        aggregatedFlow = new AggregatedSslFlow(flowId, fqdn);
        aggregatedMap->insert({ tcpKey, aggregatedFlow });
    } else {
        aggregatedFlow = dynamic_cast<AggregatedSslFlow*>(it->second);
    }
    subflows.push_back(aggregatedFlow);

    return subflows;
}

auto SslStatsCollector::processPacket(Tins::Packet const& packet,
    FlowId const& flowId,
    Tins::IP const*,
    Tins::IPv6 const*,
    Tins::TCP const* tcp,
    Tins::UDP const*) -> void
{
    if (tcp == nullptr) {
        return;
    }

    auto const* rawData = tcp->find_pdu<Tins::RawPDU>();
    if (rawData == nullptr) {
        return;
    }
    auto payload = rawData->payload();
    auto cursor = Cursor(payload);
    if (checkValidSsl(&cursor) == false) {
        return;
    }

    auto* sslFlow = lookupSslFlow(flowId);
    if (sslFlow == nullptr) {
        return;
    }
    auto direction = flowId.getDirection();
    sslFlow->addPacket(packet, direction);

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    sslFlow->updateFlow(packet, direction, *tcp);
}

auto SslStatsCollector::getSortFun(Field field) const -> sortFlowFun
{
    auto sortFun = Collector::getSortFun(field);
    if (sortFun != nullptr) {
        return sortFun;
    }
    switch (field) {
    case Field::CONN:
        return AggregatedSslFlow::sortByConnections;
    case Field::CONN_RATE:
        return AggregatedSslFlow::sortByConnectionRate;
    case Field::CT_P95:
        return AggregatedSslFlow::sortByConnectionP95;
    case Field::CT_P99:
        return AggregatedSslFlow::sortByConnectionP99;
    default:
        return nullptr;
    }
}

} // namespace flowstats
