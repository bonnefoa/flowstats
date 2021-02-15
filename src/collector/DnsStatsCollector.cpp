#include "DnsStatsCollector.hpp"
#include "PduUtils.hpp"
#include "PrintHelper.hpp"
#include <tins/memory_helpers.h>
#include <tins/rawpdu.h>

namespace flowstats {

DnsStatsCollector::DnsStatsCollector(FlowstatsConfiguration const& conf,
    DisplayConfiguration const& displayConf,
    IpToFqdn* ipToFqdn)
    : Collector { conf, displayConf }
    , ipToFqdn(ipToFqdn)
{
    getFlowFormatter().setDisplayKeys({ Field::FQDN, Field::IP, Field::PORT, Field::PROTO, Field::TYPE, Field::DIR });
    setDisplayPairs({
        DisplayFieldValues(DisplayRequests, { Field::REQ, Field::REQ_AVG, Field::TIMEOUTS, Field::TIMEOUTS_AVG }),
        DisplayFieldValues(DisplayResponses, { Field::SRT, Field::SRT_AVG, Field::SRT_P95, Field::SRT_TOTAL_P95, Field::SRT_P99, Field::SRT_TOTAL_P99 }),
        DisplayFieldValues(DisplayDnsResourceRecords, { Field::RR_A_RATE, Field::RR_AAAA_RATE, Field::RR_CNAME_RATE, Field::RR_OTHER_RATE }),
        DisplayFieldValues(DisplayClients, { Field::TOP_CLIENT_IPS_IP, Field::TOP_CLIENT_IPS_PKTS, Field::TOP_CLIENT_IPS_BYTES, Field::TOP_CLIENT_IPS_REQUESTS }, true),
        DisplayFieldValues(DisplayTraffic, { Field::PKTS, Field::PKTS_RATE, Field::BYTES, Field::BYTES_RATE }),
    });
    setTotalFlow(new DnsAggregatedFlow());
    updateDisplayType(0);
    fillSortFields();
};

auto DnsStatsCollector::isDnsPort(uint16_t port) -> bool
{
    switch (port) {
        case 53:
        case 5353:
        case 5355:
            return true;
    }
    return false;
}

auto DnsStatsCollector::isPossibleDns(Tins::TCP const* tcp, Tins::UDP const* udp) -> bool
{
    auto ports = getPorts(tcp, udp);
    if (isDnsPort(ports[0])) {
        return true;
    }
    if (isDnsPort(ports[1])) {
        return true;
    }

    return false;
}

auto DnsStatsCollector::processPacket(Tins::Packet const& packet,
    FlowId const& flowId,
    Tins::IP const*,
    Tins::IPv6 const*,
    Tins::TCP const* tcp,
    Tins::UDP const* udp) -> void
{
    auto const* pdu = packet.pdu();
    if (pdu == nullptr) {
        return;
    }
    if (!isPossibleDns(tcp, udp)) {
        return;
    }

    auto const* rawPdu = pdu->find_pdu<Tins::RawPDU>();
    if (rawPdu == nullptr) {
        return;
    }
    Tins::DNS dns;
    if (tcp) {
        auto const& payload = rawPdu->payload();
        Tins::Memory::InputMemoryStream stream(&payload[0], static_cast<uint32_t>(payload.size()));
        auto tcpSize = stream.read_be<uint16_t>();
        if (tcpSize != stream.size()) {
            return;
        }
        SPDLOG_DEBUG("Found dns on tcp with size {}", tcpSize);
        dns = Tins::DNS(stream.pointer(), static_cast<uint32_t>(stream.size()));
    } else {
        dns = rawPdu->to<Tins::DNS>();
    }

    if (dns.type() == Tins::DNS::QUERY) {
        newDnsQuery(packet, flowId, dns);
        return;
    }

    auto it = transactionIdToDnsFlow.find(dns.id());
    if (it != transactionIdToDnsFlow.end()) {
        DnsFlow* flow = &it->second;
        newDnsResponse(packet, dns, flow);
    }
}

auto DnsStatsCollector::updateIpToFqdn(Tins::DNS const& dns, std::string const& fqdn) -> void
{
    auto answers = dns.answers();
    std::vector<Tins::IPv4Address> ips;
    std::vector<Tins::IPv6Address> ipv6;
    for (auto const& answer : answers) {
        if (answer.query_type() == Tins::DNS::A) {
            ips.emplace_back(Tins::IPv4Address(answer.data()));
        } else if (answer.query_type() == Tins::DNS::AAAA) {
            ipv6.emplace_back(Tins::IPv6Address(answer.data()));
        }
    }

    ipToFqdn->updateFqdn(fqdn, ips, ipv6);
}

auto DnsStatsCollector::newDnsQuery(Tins::Packet const& packet, FlowId const& flowId, Tins::DNS const& dns) -> void
{
    auto queries = dns.queries();
    if (queries.size() == 0) {
        SPDLOG_DEBUG("No queries in {}", dns.id());
        return;
    }
    auto firstQuery = queries.at(0);
    if (firstQuery.dname().empty()) {
        SPDLOG_DEBUG("Empty query in dns tid {}", dns.id());
        return;
    }
    DnsFlow flow(packet, flowId, dns);
    transactionIdToDnsFlow[dns.id()] = std::move(flow);
}

auto DnsStatsCollector::newDnsResponse(Tins::Packet const& packet,
    Tins::DNS const& dns, DnsFlow* flow) -> void
{
    flow->processDnsResponse(packet, dns);
    addFlowToAggregation(flow);
    updateIpToFqdn(dns, flow->getFqdn());
    transactionIdToDnsFlow.erase(dns.id());
}

auto DnsStatsCollector::addFlowToAggregation(DnsFlow const* flow) -> void
{
    auto dnsType = flow->getType();
    auto fqdn = flow->getFqdn();
    auto key = AggregatedKey::aggregatedDnsKey(fqdn, dnsType, flow->getTransport());

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    auto* aggregatedMap = getAggregatedMap();
    auto it = aggregatedMap->find(key);
    DnsAggregatedFlow* aggregatedFlow;
    if (it == aggregatedMap->end()) {
        SPDLOG_DEBUG("Create new dns aggregation for {} {} {}", fqdn,
            dnsTypeToString(dnsType), flow->getTransport()._to_string());
        aggregatedFlow = new DnsAggregatedFlow(flow->getFlowId(), fqdn, dnsType);
        aggregatedMap->emplace(key, aggregatedFlow);
    } else {
        aggregatedFlow = dynamic_cast<DnsAggregatedFlow*>(it->second);
    }
    aggregatedFlow->addFlow(flow);
}

auto DnsStatsCollector::advanceTick(timeval now) -> void
{
    if (now.tv_sec <= lastTick) {
        return;
    }
    SPDLOG_DEBUG("Advancing dns tick to {}s", now.tv_sec);
    lastTick = now.tv_sec;

    // Timeout ongoing dns queries
    std::vector<uint16_t> toErase;
    for (auto& pair : transactionIdToDnsFlow) {
        DnsFlow& flow = pair.second;
        time_t delta_time = now.tv_sec - flow.getStartTv().tv_sec;
        SPDLOG_DEBUG("Flow {}, delta {}, hasResponse {}", flow.getFqdn(),
            delta_time, flow.getHasResponse());
        if (delta_time > 5) {
            addFlowToAggregation(&flow);
            toErase.push_back(pair.first);
        }
    }
    for (auto& key : toErase) {
        transactionIdToDnsFlow.erase(key);
    }
}

auto DnsStatsCollector::getSortFun(Field field) const -> sortFlowFun
{
    auto sortFun = Collector::getSortFun(field);
    if (sortFun != nullptr) {
        return sortFun;
    }
    switch (field) {
        case Field::PROTO:
            return &DnsAggregatedFlow::sortByProto;
        case Field::TYPE:
            return &DnsAggregatedFlow::sortByType;
        case Field::REQ:
            return &DnsAggregatedFlow::sortByRequest;
        case Field::REQ_RATE:
            return &DnsAggregatedFlow::sortByRequestRate;
        case Field::TIMEOUTS:
            return &DnsAggregatedFlow::sortByTimeout;
        case Field::TIMEOUTS_RATE:
            return &DnsAggregatedFlow::sortByTimeoutRate;
        case Field::SRT:
            return &DnsAggregatedFlow::sortBySrt;
        case Field::SRT_RATE:
            return &DnsAggregatedFlow::sortBySrtRate;
        case Field::SRT_TOTAL_P95:
            return &DnsAggregatedFlow::sortBySrtTotalP95;
        case Field::SRT_P95:
            return &DnsAggregatedFlow::sortBySrtP95;
        case Field::SRT_P99:
            return &DnsAggregatedFlow::sortBySrtP99;
        case Field::SRT_TOTAL_P99:
            return &DnsAggregatedFlow::sortBySrtTotalP99;
        case Field::SRT_MAX:
            return &DnsAggregatedFlow::sortBySrtMax;
        case Field::SRT_TOTAL_MAX:
            return &DnsAggregatedFlow::sortBySrtTotalMax;
        case Field::RR_A_RATE:
            return [](Flow const* a, Flow const* b) { return DnsAggregatedFlow::sortByResourceRecord(a, b, ResourceRecordType::A, false); };
        case Field::RR_AAAA_RATE:
            return [](Flow const* a, Flow const* b) { return DnsAggregatedFlow::sortByResourceRecord(a, b, ResourceRecordType::AAAA, false); };
        case Field::RR_CNAME_RATE:
            return [](Flow const* a, Flow const* b) { return DnsAggregatedFlow::sortByResourceRecord(a, b, ResourceRecordType::CNAME, false); };
        case Field::RR_PTR_RATE:
            return [](Flow const* a, Flow const* b) { return DnsAggregatedFlow::sortByResourceRecord(a, b, ResourceRecordType::PTR, false); };
        case Field::RR_OTHER_RATE:
            return [](Flow const* a, Flow const* b) { return DnsAggregatedFlow::sortByResourceRecord(a, b, ResourceRecordType::OTHER, false); };
        case Field::RR_A_AVG:
            return [](Flow const* a, Flow const* b) { return DnsAggregatedFlow::sortByResourceRecord(a, b, ResourceRecordType::A, true); };
        case Field::RR_AAAA_AVG:
            return [](Flow const* a, Flow const* b) { return DnsAggregatedFlow::sortByResourceRecord(a, b, ResourceRecordType::AAAA, true); };
        case Field::RR_CNAME_AVG:
            return [](Flow const* a, Flow const* b) { return DnsAggregatedFlow::sortByResourceRecord(a, b, ResourceRecordType::CNAME, true); };
        case Field::RR_PTR_AVG:
            return [](Flow const* a, Flow const* b) { return DnsAggregatedFlow::sortByResourceRecord(a, b, ResourceRecordType::PTR, true); };
        case Field::RR_OTHER_AVG:
            return [](Flow const* a, Flow const* b) { return DnsAggregatedFlow::sortByResourceRecord(a, b, ResourceRecordType::OTHER, true); };
        default:
            return nullptr;
    }
}
} // namespace flowstats
