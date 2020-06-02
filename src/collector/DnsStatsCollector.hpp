#pragma once

#include "AggregatedDnsFlow.hpp"
#include "AggregatedKeys.hpp"
#include "Collector.hpp"
#include "Configuration.hpp"
#include "DnsFlow.hpp"
#include "IpToFqdn.hpp"
#include "Utils.hpp"

namespace flowstats {

class DnsStatsCollector : public Collector {
public:
    DnsStatsCollector(FlowstatsConfiguration const& conf,
        DisplayConfiguration const& displayConf,
        IpToFqdn* ipToFqdn);

    auto processPacket(Tins::Packet const& packet,
        FlowId const& flowId,
        Tins::IP const* ip,
        Tins::IPv6 const* ipv6,
        Tins::TCP const* tcp,
        Tins::UDP const* udp) -> void override;
    auto advanceTick(timeval now) -> void override;

    [[nodiscard]] auto toString() const -> std::string override { return "DnsStatsCollector"; }
    [[nodiscard]] auto getProtocol() const -> CollectorProtocol override { return DNS; };

private:
    auto isDnsPort(uint16_t port) -> bool;
    auto isPossibleDns(Tins::TCP const* tcp, Tins::UDP const* udp) -> bool;

    auto newDnsQuery(Tins::Packet const& packet,
        FlowId const& flowId,
        Tins::DNS const& dns) -> void;
    auto newDnsResponse(Tins::Packet const& packet, Tins::DNS const& dns, DnsFlow* flow) -> void;
    auto updateIpToFqdn(Tins::DNS const& dns, std::string const& fqdn) -> void;
    auto addFlowToAggregation(DnsFlow const* flow) -> void;
    [[nodiscard]] auto getSortFun(Field field) const -> sortFlowFun override;

    IpToFqdn* ipToFqdn;
    std::map<uint16_t, DnsFlow> transactionIdToDnsFlow;
    time_t lastTick = 0;
};
} // namespace flowstats
