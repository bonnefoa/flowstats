#pragma once

#include "AggregatedDnsFlow.hpp"
#include "Collector.hpp"
#include "Configuration.hpp"
#include "DnsFlow.hpp"
#include "Utils.hpp"
#include <DnsLayer.h>
#include <PacketUtils.h>
#include <TcpLayer.h>
#include <spdlog/spdlog.h>

namespace flowstats {

class DnsStatsCollector : public Collector {
public:
    DnsStatsCollector(FlowstatsConfiguration& conf,
        DisplayConfiguration& displayConf);
    ~DnsStatsCollector();

    void processPacket(Tins::Packet* packet);
    std::vector<std::string> getMetrics();
    std::string getFlowName() { return "DNS"; }
    std::string toString() { return "DnsStatsCollector"; }
    std::vector<Flow*> getFlows();
    std::map<AggregatedDnsKey, AggregatedDnsFlow*> getAggregatedFlow()
    {
        return aggregatedDnsFlows;
    }
    void advanceTick(timeval now);
    void resetMetrics();
    std::vector<AggregatedPairPointer> getAggregatedPairs();
    void mergePercentiles();
    Tins::ProtocolType getProtocol() { return Tins::DNS; };

private:
    void newDnsQuery(Tins::dnshdr* hdr, timeval pktTs,
        Tins::DnsLayer* dnsLayer, Tins::Packet* packet);
    void newDnsResponse(Tins::dnshdr* hdr, timeval pktTs, Tins::DnsLayer* dnsLayer,
        Tins::Packet* packet, DnsFlow& flow);
    void updateIpToFqdn(Tins::DnsLayer* dnsLayer, const std::string& fqdn);

    void addFlowToAggregation(DnsFlow& flow);
    std::map<uint16_t, DnsFlow> transactionIdToDnsFlow;
    std::vector<DnsFlow> dnsFlows;
    std::map<AggregatedDnsKey, AggregatedDnsFlow*> aggregatedDnsFlows;
    time_t lastTick = 0;
};
}
