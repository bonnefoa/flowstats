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

using hashFlow = std::pair<uint32_t, SslFlow>;

class SslStatsCollector : public Collector {
public:
    SslStatsCollector(FlowstatsConfiguration const& conf, DisplayConfiguration const& displayConf, IpToFqdn* ipToFqdn);

    auto processPacket(Tins::Packet const& packet) -> void override;

    auto getProtocol() const -> CollectorProtocol override { return SSL; };
    auto toString() const -> std::string override { return "SslStatsCollector"; }

    [[nodiscard]] auto getSslFlow() const -> std::map<uint32_t, SslFlow> { return hashToSslFlow; }

private:
    std::map<uint32_t, SslFlow> hashToSslFlow;
    auto getSortFun(Field field) const -> sortFlowFun override;
    auto lookupSslFlow(FlowId const& flowId) -> SslFlow*;
    auto lookupAggregatedFlows(FlowId const& flowId, std::string const& fqdn, Direction srvDir) -> std::vector<AggregatedSslFlow*>;
    IpToFqdn* ipToFqdn;
};
} // namespace flowstats
