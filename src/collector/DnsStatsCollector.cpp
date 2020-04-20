#include "DnsStatsCollector.hpp"
#include "PrintHelper.hpp"

namespace flowstats {

DnsStatsCollector::DnsStatsCollector(FlowstatsConfiguration& conf, DisplayConfiguration& displayConf)
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

void DnsStatsCollector::processPacket(Tins::Packet* packet)
{
    timeval pktTs = packet->getRawPacket()->getPacketTimeStamp();
    advanceTick(pktTs);
    if (packet->isPacketOfType(Tins::IPv6) || !packet->isPacketOfType(Tins::DNS)) {
        return;
    }
    auto* dnsLayer = packet->getLayerOfType<Tins::DnsLayer>(true);

    Tins::dnshdr* hdr = dnsLayer->getDnsHeader();
    if (hdr->queryOrResponse == 0 && dnsLayer->getFirstQuery() != nullptr) {
        newDnsQuery(hdr, pktTs, dnsLayer, packet);
        return;
    }

    auto it = transactionIdToDnsFlow.find(hdr->transactionID);
    if (it != transactionIdToDnsFlow.end()) {
        DnsFlow& flow = it->second;
        newDnsResponse(hdr, pktTs, dnsLayer, packet, flow);
    }
}

auto DnsStatsCollector::getFlows() -> std::vector<Flow*>
{
    std::vector<Flow*> res;
    for (auto& flow : dnsFlows) {
        res.push_back(&flow);
    }
    return res;
}

void DnsStatsCollector::updateIpToFqdn(Tins::DnsLayer* dnsLayer, const std::string& fqdn)
{
    Tins::DnsResource* answer = dnsLayer->getFirstAnswer();
    std::vector<int> ips;
    while (answer != nullptr) {
        answer->getData()->toString();
        if (answer->getData()->isTypeOf<Tins::IPv4DnsResourceData>()) {
            ips.push_back(answer->getData()
                              ->castAs<Tins::IPv4DnsResourceData>()
                              ->getIpAddress()
                              .toInt());
        }
        answer = dnsLayer->getNextAnswer(answer);
    }
    {
        const std::lock_guard<std::mutex> lock(conf.ipToFqdnMutex);
        for (auto ip : ips) {
            conf.ipToFqdn[ip] = fqdn;
        }
    }
}

void DnsStatsCollector::newDnsQuery(Tins::dnshdr* hdr, timeval pktTs, Tins::DnsLayer* dnsLayer, Tins::Packet* packet)
{
    DnsFlow flow(packet);
    flow.addPacket(packet, FROM_CLIENT);
    flow.m_StartTimestamp = pktTs;
    flow.isTcp = packet->isPacketOfType(Tins::TCP);
    flow.type = dnsLayer->getFirstQuery()->getDnsType();
    flow.fqdn = std::string(dnsLayer->getFirstQuery()->getName());
    flow.hasResponse = false;
    if (dnsLayer->getFirstQuery()->getName().empty()) {
        spdlog::debug("Empty query in dns {}", dnsLayer->toString());
        return;
    }
    transactionIdToDnsFlow[hdr->transactionID] = flow;
}

void DnsStatsCollector::newDnsResponse(Tins::dnshdr* hdr, timeval pktTs,
    Tins::DnsLayer* dnsLayer, Tins::Packet* packet, DnsFlow& flow)
{
    flow.addPacket(packet, FROM_SERVER);
    flow.m_EndTimestamp = pktTs;
    flow.hasResponse = true;
    flow.truncated = hdr->truncation;
    flow.numberRecords = dnsLayer->getAnswerCount();
    flow.responseCode = hdr->responseCode;

    updateIpToFqdn(dnsLayer, flow.fqdn);
    spdlog::debug("Dns tid {}, {}, {} finished, {}", hdr->transactionID,
        flow.isTcp ? "Tcp" : "Udp",
        flow.fqdn,
        flow.numberRecords);
    dnsFlows.push_back(flow);
    addFlowToAggregation(flow);
    transactionIdToDnsFlow.erase(hdr->transactionID);
}

void DnsStatsCollector::addFlowToAggregation(DnsFlow& flow)
{
    AggregatedDnsKey key(flow.fqdn, flow.type, flow.isTcp);

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    auto it = aggregatedDnsFlows.find(key);
    AggregatedDnsFlow* aggregatedFlow;
    if (it == aggregatedDnsFlows.end()) {
        spdlog::debug("Create new dns aggregation for {} {} {}", flow.fqdn,
            dnsTypeToString(flow.type), flow.isTcp);
        aggregatedFlow = new AggregatedDnsFlow(flow.flowId, flow.fqdn, flow.type, flow.isTcp);
        aggregatedDnsFlows[key] = aggregatedFlow;
    } else {
        aggregatedFlow = it->second;
    }
    aggregatedFlow->addFlow(&flow);
}

void DnsStatsCollector::advanceTick(timeval now)
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
        time_t delta_time = now.tv_sec - flow.m_StartTimestamp.tv_sec;
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
            { "proto", val->isTcp ? "tcp" : "udp" },
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

void DnsStatsCollector::mergePercentiles()
{
    for (auto& pair : aggregatedDnsFlows) {
        pair.second->srts.merge();
    }
}

void DnsStatsCollector::resetMetrics()
{
    const std::lock_guard<std::mutex> lock(*getDataMutex());
    for (auto& pair : aggregatedDnsFlows) {
        pair.second->resetFlow(false);
    }
}

auto sortAggregatedDnsBySrt(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    auto* rightDns = dynamic_cast<AggregatedDnsFlow*>(right.second);
    auto* leftDns = dynamic_cast<AggregatedDnsFlow*>(left.second);
    return rightDns->srts.getPercentile(1.0) < leftDns->srts.getPercentile(1.0);
}

auto sortAggregatedDnsByRequest(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    auto* rightDns = dynamic_cast<AggregatedDnsFlow*>(right.second);
    auto* leftDns = dynamic_cast<AggregatedDnsFlow*>(left.second);
    return rightDns->totalQueries < leftDns->totalQueries;
}

auto sortAggregatedDnsByRequestRate(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    auto* rightDns = dynamic_cast<AggregatedDnsFlow*>(right.second);
    auto* leftDns = dynamic_cast<AggregatedDnsFlow*>(left.second);
    return rightDns->queries < leftDns->queries;
}

auto DnsStatsCollector::getAggregatedPairs() -> std::vector<AggregatedPairPointer>
{
    std::vector<AggregatedPairPointer> tempVector(aggregatedDnsFlows.begin(),
        aggregatedDnsFlows.end());

    bool (*sortFunc)(const AggregatedPairPointer& left,
        const AggregatedPairPointer& right)
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
