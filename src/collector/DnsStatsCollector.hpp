#pragma once

#include "AggregatedDnsFlow.hpp"
#include "Collector.hpp"
#include "Configuration.hpp"
#include "DnsFlow.hpp"
#include "Utils.hpp"
#include <spdlog/spdlog.h>

namespace flowstats {

class DnsStatsCollector : public Collector {
public:
    DnsStatsCollector(FlowstatsConfiguration& conf,
        DisplayConfiguration& displayConf);
    ~DnsStatsCollector();

    void processPacket(Tins::PtrPacket& packet);
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
    Tins::PDU::PDUType getProtocol() { return Tins::PDU::DNS; };

private:
    void newDnsQuery(Tins::PtrPacket& packet, Tins::DNS* dns);
    void newDnsResponse(Tins::PtrPacket& packet, Tins::DNS* dns, DnsFlow& flow);
    void updateIpToFqdn(Tins::DNS* dns, const std::string& fqdn);

    void addFlowToAggregation(DnsFlow& flow);
    std::map<uint16_t, DnsFlow> transactionIdToDnsFlow;
    std::vector<DnsFlow> dnsFlows;
    std::map<AggregatedDnsKey, AggregatedDnsFlow*> aggregatedDnsFlows;
    time_t lastTick = 0;
};
}
