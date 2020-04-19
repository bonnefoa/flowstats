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

    void processPacket(pcpp::Packet* packet);
    std::vector<std::string> getMetrics();
    std::string getFlowName() { return "DNS"; }
    std::string toString() { return "DnsStatsCollector"; }
    std::vector<Flow*> getFlows();
    std::map<AggregatedDnsKey, AggregatedDnsFlow*> getAggregatedFlow()
    {
        return aggregatedDnsFlows;
    }
    void advanceTick(timespec now);
    void resetMetrics();
    std::vector<AggregatedPairPointer> getAggregatedPairs();
    void mergePercentiles();
    pcpp::ProtocolType getProtocol() { return pcpp::DNS; };

private:
    void newDnsQuery(pcpp::dnshdr* hdr, timespec pktTs,
        pcpp::DnsLayer* dnsLayer, pcpp::Packet* packet);
    void newDnsResponse(pcpp::dnshdr* hdr, timespec pktTs, pcpp::DnsLayer* dnsLayer,
        pcpp::Packet* packet, DnsFlow& flow);
    void updateIpToFqdn(pcpp::DnsLayer* dnsLayer, const std::string& fqdn);

    void addFlowToAggregation(DnsFlow& flow);
    std::map<uint16_t, DnsFlow> transactionIdToDnsFlow;
    std::vector<DnsFlow> dnsFlows;
    std::map<AggregatedDnsKey, AggregatedDnsFlow*> aggregatedDnsFlows;
    time_t lastTick = 0;
};
}
