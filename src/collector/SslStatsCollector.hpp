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

    [[nodiscard]] auto getProtocol() const -> CollectorProtocol override { return SSL; };
    [[nodiscard]] auto toString() const -> std::string override { return "SslStatsCollector"; }

    [[nodiscard]] auto getSslFlow() const -> std::map<uint32_t, SslFlow> { return hashToSslFlow; }

private:
    std::map<uint32_t, SslFlow> hashToSslFlow;
    [[nodiscard]] auto getSortFun(Field field) const -> sortFlowFun override;
    auto lookupSslFlow(FlowId const& flowId) -> SslFlow*;
    auto lookupAggregatedFlows(FlowId const& flowId, std::string const& fqdn, Direction srvDir) -> std::vector<AggregatedSslFlow*>;
    IpToFqdn* ipToFqdn;
};
} // namespace flowstats
