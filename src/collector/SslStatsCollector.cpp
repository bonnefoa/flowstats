#include "SslStatsCollector.hpp"
#include "SslProto.hpp"
#include <fmt/format.h>
#include <tins/memory_helpers.h>
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
        DisplayFieldValues(DisplayConnections, { Field::CONN }),
        DisplayFieldValues(DisplayConnectionTimes, { Field::CT_P95, Field::CT_TOTAL_P95, Field::CT_P99, Field::CT_TOTAL_P99 }),
        DisplayFieldValues(DisplaySsl, { Field::DOMAIN, Field::TLS_VERSION, Field::CIPHER_SUITE }),
        DisplayFieldValues(DisplayTraffic, { Field::PKTS, Field::PKTS_RATE, Field::BYTES, Field::BYTES_RATE }),
    });
    setTotalFlow(new SslAggregatedFlow());
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

auto SslStatsCollector::lookupAggregatedFlows(FlowId const& flowId, std::string const& fqdn, Direction srvDir) -> std::vector<SslAggregatedFlow*>
{
    std::vector<SslAggregatedFlow*> subflows;
    IPAddress ipSrvInt = {};
    if (getFlowstatsConfiguration().getPerIpAggr()) {
        ipSrvInt = flowId.getIp(srvDir);
    }
    auto tcpKey = AggregatedKey(fqdn, ipSrvInt, flowId.getPort(srvDir));
    SslAggregatedFlow* aggregatedFlow;

    auto* aggregatedMap = getAggregatedMap();
    auto it = aggregatedMap->find(tcpKey);
    if (it == aggregatedMap->end()) {
        aggregatedFlow = new SslAggregatedFlow(flowId, fqdn);
        aggregatedMap->insert({ tcpKey, aggregatedFlow });
    } else {
        aggregatedFlow = dynamic_cast<SslAggregatedFlow*>(it->second);
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
    auto mbTlsHeader = TlsHeader::parse(&cursor);
    if (!mbTlsHeader) {
        return;
    }

    auto* sslFlow = lookupSslFlow(flowId);
    if (sslFlow == nullptr) {
        return;
    }
    auto direction = flowId.getDirection();
    const std::lock_guard<std::mutex> lock(*getDataMutex());
    sslFlow->addPacket(packet, direction);
    sslFlow->updateFlow(packet, *tcp);
}

auto SslStatsCollector::getSortFun(Field field) const -> sortFlowFun
{
    auto sortFun = Collector::getSortFun(field);
    if (sortFun != nullptr) {
        return sortFun;
    }
    switch (field) {
        case Field::CONN:
            return SslAggregatedFlow::sortByConnections;
        case Field::CONN_RATE:
            return SslAggregatedFlow::sortByConnectionRate;
        case Field::DOMAIN:
            return SslAggregatedFlow::sortByDomain;
        case Field::CIPHER_SUITE:
            return SslAggregatedFlow::sortByCipherSuite;
        case Field::TLS_VERSION:
            return SslAggregatedFlow::sortByTlsVersion;
        case Field::CT_P95:
            return [](Flow const* a, Flow const* b) { return SslAggregatedFlow::sortByConnectionPercentile(a, b, 0.95, false); };
        case Field::CT_TOTAL_P95:
            return [](Flow const* a, Flow const* b) { return SslAggregatedFlow::sortByConnectionPercentile(a, b, 0.95, true); };
        case Field::CT_P99:
            return [](Flow const* a, Flow const* b) { return SslAggregatedFlow::sortByConnectionPercentile(a, b, 0.99, false); };
        case Field::CT_TOTAL_P99:
            return [](Flow const* a, Flow const* b) { return SslAggregatedFlow::sortByConnectionPercentile(a, b, 0.99, true); };
        default:
            return nullptr;
    }
}

} // namespace flowstats
