#pragma once

#include "AggregatedKeys.hpp"
#include "AggregatedSslFlow.hpp"
#include "Collector.hpp"
#include "IpToFqdn.hpp"
#include "PrintHelper.hpp"
#include "SslFlow.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <iostream>
#include <map>
#include <sstream>

namespace flowstats {

class SslStatsCollector : public Collector {
public:
    SslStatsCollector(FlowstatsConfiguration const& conf, DisplayConfiguration const& displayConf, IpToFqdn* ipToFqdn);

    auto processPacket(Tins::Packet const& packet,
        FlowId const& flowId,
        Tins::IP const* ip,
        Tins::IPv6 const* ipv6,
        Tins::TCP const* tcp,
        Tins::UDP const* udp) -> void override;

    [[nodiscard]] auto getProtocol() const -> CollectorProtocol override { return CollectorProtocol::SSL; };
    [[nodiscard]] auto toString() const -> std::string override { return "SslStatsCollector"; }

    [[nodiscard]] auto getSslFlow() const { return hashToSslFlow; }

private:
    std::unordered_map<FlowId, SslFlow, std::hash<FlowId>> hashToSslFlow;
    [[nodiscard]] auto getSortFun(Field field) const -> sortFlowFun override;
    auto lookupSslFlow(FlowId const& flowId) -> SslFlow*;
    auto lookupAggregatedFlows(FlowId const& flowId, std::string const& fqdn, Direction srvDir) -> std::vector<AggregatedSslFlow*>;
    IpToFqdn* ipToFqdn;
};
} // namespace flowstats
