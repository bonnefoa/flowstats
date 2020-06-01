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

    auto const* fqdn = fqdnOpt->data();
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
