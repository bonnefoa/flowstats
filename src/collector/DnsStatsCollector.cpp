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
        DisplayPair(DisplayResponses, { Field::SRT, Field::SRT_RATE, Field::SRT_P95, Field::SRT_P99, Field::RCRD_RSP }),
        DisplayPair(DisplayClients, { Field::TOP_CLIENT_IPS }),
        DisplayPair(DisplayTraffic, { Field::PKTS, Field::PKTS_RATE, Field::BYTES, Field::BYTES_RATE }),
    });
    setTotalFlow(new AggregatedDnsFlow());
    updateDisplayType(0);
};

auto DnsStatsCollector::processPacket(Tins::Packet const& packet) -> void
{
    timeval pktTs = packetToTimeval(packet);
    advanceTick(pktTs);
    auto const* pdu = packet.pdu();
    auto dns = pdu->rfind_pdu<Tins::RawPDU>().to<Tins::DNS>();

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
    AggregatedDnsKey key(fqdn, dnsType, flow->flowId.transport);

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    auto it = aggregatedDnsFlows.find(key);
    AggregatedDnsFlow* aggregatedFlow;
    if (it == aggregatedDnsFlows.end()) {
        spdlog::debug("Create new dns aggregation for {} {} {}", fqdn,
            dnsTypeToString(dnsType), flow->flowId.transport);
        aggregatedFlow = new AggregatedDnsFlow(flow->flowId, fqdn, dnsType);
        aggregatedDnsFlows[key] = aggregatedFlow;
    } else {
        aggregatedFlow = it->second;
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

auto DnsStatsCollector::getMetrics() -> std::vector<std::string>
{
    std::vector<std::string> res;
    for (auto& pair : aggregatedDnsFlows) {
        struct AggregatedDnsFlow* val = pair.second;
        auto dnsMetrics = val->getStatsdMetrics();
        res.insert(res.end(), dnsMetrics.begin(), dnsMetrics.end());
    }
    return res;
}

auto DnsStatsCollector::mergePercentiles() -> void
{
    for (auto& pair : aggregatedDnsFlows) {
        pair.second->mergePercentiles();
    }
}

auto DnsStatsCollector::resetMetrics() -> void
{
    const std::lock_guard<std::mutex> lock(*getDataMutex());
    for (auto& pair : aggregatedDnsFlows) {
        pair.second->resetFlow(false);
    }
}

auto sortAggregatedDnsBySrt(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    auto* rightDns = dynamic_cast<AggregatedDnsFlow*>(right.second);
    auto* leftDns = dynamic_cast<AggregatedDnsFlow*>(left.second);
    if (rightDns == nullptr || leftDns == nullptr) {
        return false;
    }
    return rightDns->sortBySrt(*leftDns);
}

auto sortAggregatedDnsByRequest(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    auto* rightDns = dynamic_cast<AggregatedDnsFlow*>(right.second);
    auto* leftDns = dynamic_cast<AggregatedDnsFlow*>(left.second);
    if (rightDns == nullptr || leftDns == nullptr) {
        return false;
    }
    return rightDns->sortByRequest(*leftDns);
}

auto sortAggregatedDnsByRequestRate(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    auto* rightDns = dynamic_cast<AggregatedDnsFlow*>(right.second);
    auto* leftDns = dynamic_cast<AggregatedDnsFlow*>(left.second);
    if (rightDns == nullptr || leftDns == nullptr) {
        return false;
    }
    return rightDns->sortByRequestRate(*leftDns);
}

auto DnsStatsCollector::getAggregatedPairs() const -> std::vector<AggregatedPairPointer>
{
    std::vector<AggregatedPairPointer> tempVector(aggregatedDnsFlows.begin(),
        aggregatedDnsFlows.end());

    bool (*sortFunc)(AggregatedPairPointer const& left,
        AggregatedPairPointer const& right)
        = sortAggregatedDnsByRequest;
    switch (getDisplayConf().sortType) {
    case SortFqdn:
        sortFunc = sortAggregatedPairByFqdn;
        break;
    case SortByte:
        sortFunc = sortAggregatedPairByByte;
        break;
    case SortPacket:
        sortFunc = sortAggregatedPairByPacket;
        break;
    case SortRequest:
        sortFunc = sortAggregatedDnsByRequest;
        break;
    case SortRequestRate:
        sortFunc = sortAggregatedDnsByRequestRate;
        break;
    case SortSrt:
        sortFunc = sortAggregatedDnsBySrt;
        break;
    }
    std::sort(tempVector.begin(), tempVector.end(), sortFunc);

    return tempVector;
}

DnsStatsCollector::~DnsStatsCollector()
{
    for (auto& pair : aggregatedDnsFlows) {
        delete pair.second;
    }
}
} // namespace flowstats
