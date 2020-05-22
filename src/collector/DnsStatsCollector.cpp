#include "DnsStatsCollector.hpp"
#include "PrintHelper.hpp"
#include "tins/rawpdu.h"

namespace flowstats {

DnsStatsCollector::DnsStatsCollector(FlowstatsConfiguration const& conf,
    DisplayConfiguration const& displayConf,
    IpToFqdn* ipToFqdn)
    : Collector { conf, displayConf }
    , ipToFqdn(ipToFqdn)
{
    getFlowFormatter().setDisplayKeys({ Field::FQDN, Field::IP, Field::PORT, Field::PROTO, Field::TYPE, Field::DIR });
    setDisplayPairs({
        DisplayPair(DisplayRequests, { Field::REQ, Field::REQ_RATE, Field::TIMEOUTS, Field::TIMEOUTS_RATE }),
        DisplayPair(DisplayResponses, { Field::SRT, Field::SRT_RATE, Field::SRT_P95, Field::SRT_P99, Field::RCRD_AVG }),
        DisplayPair(DisplayClients, { Field::TOP_CLIENT_IPS }),
        DisplayPair(DisplayTraffic, { Field::PKTS, Field::PKTS_RATE, Field::BYTES, Field::BYTES_RATE }),
    });
    setTotalFlow(new AggregatedDnsFlow());
    fillSortFields();
    updateDisplayType(0);
};

auto DnsStatsCollector::processPacket(Tins::Packet const& packet) -> void
{
    timeval pktTs = packetToTimeval(packet);
    advanceTick(pktTs);
    auto const* pdu = packet.pdu();
    auto rawPdu = pdu->find_pdu<Tins::RawPDU>();
    if (rawPdu == nullptr) {
        return;
    }
    // TODO Avoid exception
    auto dns = rawPdu->to<Tins::DNS>();

    if (dns.type() == Tins::DNS::QUERY) {
        newDnsQuery(packet, dns);
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
    for (auto const& answer : answers) {
        if (answer.query_type() == Tins::DNS::A) {
            ips.emplace_back(Tins::IPv4Address(answer.data()));
        }
    }

    ipToFqdn->updateFqdn(fqdn, ips);
}

auto DnsStatsCollector::newDnsQuery(Tins::Packet const& packet, Tins::DNS const& dns) -> void
{
    auto queries = dns.queries();
    if (queries.size() == 0) {
        spdlog::debug("No queries in {}", dns.id());
        return;
    }
    auto firstQuery = queries.at(0);
    if (firstQuery.dname().empty()) {
        spdlog::debug("Empty query in dns tid {}", dns.id());
        return;
    }
    DnsFlow flow(packet, dns);
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
    AggregatedDnsKey key(fqdn, dnsType, flow->getTransport());

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    auto* aggregatedMap = getAggregatedMap();
    auto it = aggregatedMap->find(key);
    AggregatedDnsFlow* aggregatedFlow;
    if (it == aggregatedMap->end()) {
        spdlog::debug("Create new dns aggregation for {} {} {}", fqdn,
            dnsTypeToString(dnsType), flow->getTransport());
        aggregatedFlow = new AggregatedDnsFlow(flow->getFlowId(), fqdn, dnsType);
        aggregatedMap->emplace(key, aggregatedFlow);
    } else {
        aggregatedFlow = static_cast<AggregatedDnsFlow*>(it->second);
    }
    aggregatedFlow->addFlow(flow);
}

auto DnsStatsCollector::advanceTick(timeval now) -> void
{
    if (now.tv_sec <= lastTick) {
        return;
    }
    spdlog::debug("Advancing dns tick to {}s", now.tv_sec);
    lastTick = now.tv_sec;

    // Timeout ongoing dns queries
    std::vector<uint16_t> toErase;
    for (auto& pair : transactionIdToDnsFlow) {
        DnsFlow& flow = pair.second;
        time_t delta_time = now.tv_sec - flow.getStartTv().tv_sec;
        spdlog::debug("Flow {}, delta {}, hasResponse {}", flow.getFqdn(),
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
        return &AggregatedDnsFlow::sortByProto;
    case Field::TYPE:
        return &AggregatedDnsFlow::sortByType;
    case Field::REQ:
        return &AggregatedDnsFlow::sortByRequest;
    case Field::REQ_RATE:
        return &AggregatedDnsFlow::sortByRequestRate;
    case Field::TIMEOUTS:
        return &AggregatedDnsFlow::sortByTimeout;
    case Field::TIMEOUTS_RATE:
        return &AggregatedDnsFlow::sortByTimeoutRate;
    case Field::SRT:
        return &AggregatedDnsFlow::sortBySrt;
    case Field::SRT_RATE:
        return &AggregatedDnsFlow::sortBySrtRate;
    case Field::SRT_P95:
        return &AggregatedDnsFlow::sortBySrtP95;
    case Field::SRT_P99:
        return &AggregatedDnsFlow::sortBySrtP99;
    case Field::SRT_MAX:
        return &AggregatedDnsFlow::sortBySrtMax;
    case Field::RCRD_AVG:
        return &AggregatedDnsFlow::sortByRcrdAvg;
    default:
        return nullptr;
    }
}
} // namespace flowstats
