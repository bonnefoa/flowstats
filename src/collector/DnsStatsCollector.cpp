#include "DnsStatsCollector.hpp"
#include "PrintHelper.hpp"
#include "rawpdu.h"

namespace flowstats {

DnsStatsCollector::DnsStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration const& displayConf)
    : Collector { conf, displayConf }
{
    flowFormatter.setDisplayKeys({ "fqdn", "ip", "port", "proto", "type", "dir" });
    displayPairs = {
        DisplayPair(DisplayRequests, { "req", "req_s", "timeout", "timeout_s" }),
        DisplayPair(DisplayResponses, { "srt", "srt_s", "srt95", "srt99", "rcrd_rsp" }),
        DisplayPair(DisplayClients, { "top_client_ips" }),
        DisplayPair(DisplayTraffic, { "pkts", "pkts_s", "bytes", "bytes_s" }),
    };
    totalFlow = new AggregatedDnsFlow();
    updateDisplayType(0);
};

auto DnsStatsCollector::processPacket(Tins::Packet const& packet) -> void
{
    timeval pktTs = packetToTimeval(packet);
    advanceTick(pktTs);
    auto pdu = packet.pdu();
    auto dns = pdu->rfind_pdu<Tins::RawPDU>().to<Tins::DNS>();

    if (dns.type() == Tins::DNS::QUERY) {
        newDnsQuery(packet, dns);
        return;
    }

    auto it = transactionIdToDnsFlow.find(dns.id());
    if (it != transactionIdToDnsFlow.end()) {
        DnsFlow& flow = it->second;
        newDnsResponse(packet, dns, flow);
    }
}

auto DnsStatsCollector::updateIpToFqdn(Tins::DNS const& dns, std::string const& fqdn) -> void
{
    auto answers = dns.answers();
    std::vector<Tins::IPv4Address> ips;
    for (auto answer : answers) {
        if (answer.query_type() == Tins::DNS::A) {
            ips.push_back(Tins::IPv4Address(answer.data()));
        }
    }

    {
        const std::lock_guard<std::mutex> lock(conf.ipToFqdnMutex);
        for (auto ip : ips) {
            spdlog::debug("Fqdn mapping {} -> {}", ip.to_string(), fqdn);
            conf.ipToFqdn[ip] = fqdn;
        }
    }
}

auto DnsStatsCollector::newDnsQuery(Tins::Packet const& packet, Tins::DNS const& dns) -> void
{
    DnsFlow flow(packet);
    flow.addPacket(packet, FROM_CLIENT);
    flow.startTv = packetToTimeval(packet);
    auto queries = dns.queries();
    if (queries.size() == 0) {
        spdlog::debug("No queries in {}", dns.id());
        return;
    }
    auto firstQuery = queries.at(0);
    flow.type = firstQuery.query_type();
    flow.fqdn = firstQuery.dname();
    flow.hasResponse = false;
    if (flow.fqdn.empty()) {
        spdlog::debug("Empty query in dns tid {}", dns.id());
        return;
    }
    transactionIdToDnsFlow[dns.id()] = flow;
}

auto DnsStatsCollector::newDnsResponse(Tins::Packet const& packet, Tins::DNS const& dns, DnsFlow& flow) -> void
{
    flow.addPacket(packet, FROM_SERVER);
    flow.endTv = packetToTimeval(packet);
    flow.hasResponse = true;
    flow.truncated = dns.truncated();
    flow.numberRecords = dns.answers_count();
    flow.responseCode = dns.rcode();

    updateIpToFqdn(dns, flow.fqdn);
    spdlog::debug("Dns tid {}, {}, {} finished, {}", dns.id(),
        flow.flowId.isTcp ? "Tcp" : "Udp",
        flow.fqdn,
        flow.numberRecords);
    dnsFlows.push_back(flow);
    addFlowToAggregation(flow);
    transactionIdToDnsFlow.erase(dns.id());
}

auto DnsStatsCollector::addFlowToAggregation(DnsFlow const& flow) -> void
{
    AggregatedDnsKey key(flow.fqdn, flow.type, flow.flowId.isTcp);

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    auto it = aggregatedDnsFlows.find(key);
    AggregatedDnsFlow* aggregatedFlow;
    if (it == aggregatedDnsFlows.end()) {
        spdlog::debug("Create new dns aggregation for {} {} {}", flow.fqdn,
            dnsTypeToString(flow.type), flow.flowId.isTcp);
        aggregatedFlow = new AggregatedDnsFlow(flow.flowId, flow.fqdn, flow.type);
        aggregatedDnsFlows[key] = aggregatedFlow;
    } else {
        aggregatedFlow = it->second;
    }
    aggregatedFlow->addFlow(&flow);
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
        time_t delta_time = now.tv_sec - flow.startTv.tv_sec;
        spdlog::debug("Flow {}, delta {}, hasResponse {}", flow.fqdn,
            delta_time, flow.hasResponse);
        if (delta_time > 5) {
            addFlowToAggregation(flow);
            toErase.push_back(pair.first);
        }
    }
    for (auto& key : toErase) {
        transactionIdToDnsFlow.erase(key);
    }
}

auto DnsStatsCollector::getMetrics() -> std::vector<std::string>
{
    std::vector<std::string> lst;
    for (auto& pair : aggregatedDnsFlows) {
        struct AggregatedDnsFlow* val = pair.second;
        DogFood::Tags tags = DogFood::Tags({
            { "fqdn", val->fqdn },
            { "proto", val->flowId.isTcp ? "tcp" : "udp" },
            { "type", dnsTypeToString(val->dnsType) },
        });
        if (val->queries) {
            lst.push_back(DogFood::Metric("flowstats.dns.queries", val->queries,
                DogFood::Counter, 1, tags));
        }
        if (val->timeouts) {
            lst.push_back(DogFood::Metric("flowstats.dns.timeouts", val->timeouts, DogFood::Counter, 1,
                tags));
        }
        if (val->records) {
            lst.push_back(DogFood::Metric("flowstats.dns.records", val->totalRecords / val->totalQueries, DogFood::Counter, 1,
                tags));
        }
        if (val->truncated) {
            lst.push_back(DogFood::Metric("flowstats.dns.truncated", val->truncated, DogFood::Counter, 1,
                tags));
        }
    }
    return lst;
}

auto DnsStatsCollector::mergePercentiles() -> void
{
    for (auto& pair : aggregatedDnsFlows) {
        pair.second->srts.merge();
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
    return rightDns->srts.getPercentile(1.0) < leftDns->srts.getPercentile(1.0);
}

auto sortAggregatedDnsByRequest(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    auto* rightDns = dynamic_cast<AggregatedDnsFlow*>(right.second);
    auto* leftDns = dynamic_cast<AggregatedDnsFlow*>(left.second);
    return rightDns->totalQueries < leftDns->totalQueries;
}

auto sortAggregatedDnsByRequestRate(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    auto* rightDns = dynamic_cast<AggregatedDnsFlow*>(right.second);
    auto* leftDns = dynamic_cast<AggregatedDnsFlow*>(left.second);
    return rightDns->queries < leftDns->queries;
}

auto DnsStatsCollector::getAggregatedPairs() const -> std::vector<AggregatedPairPointer>
{
    std::vector<AggregatedPairPointer> tempVector(aggregatedDnsFlows.begin(),
        aggregatedDnsFlows.end());

    bool (*sortFunc)(AggregatedPairPointer const& left,
        AggregatedPairPointer const& right)
        = sortAggregatedDnsByRequest;
    switch (displayConf.sortType) {
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
    delete totalFlow;
}
} // namespace flowstats
