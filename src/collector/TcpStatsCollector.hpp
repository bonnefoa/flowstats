#pragma once

#include "Collector.hpp"
#include "IpToFqdn.hpp"
#include "TcpAggregatedFlow.hpp"
#include "TcpFlow.hpp"

namespace flowstats {

class TcpStatsCollector : public Collector {
public:
    TcpStatsCollector(FlowstatsConfiguration const& conf,
        DisplayConfiguration const& displayConf,
        IpToFqdn* ipToFqdn);

    auto processPacket(Tins::Packet const& packet,
        FlowId const& flowId,
        Tins::IP const* ip,
        Tins::IPv6 const* ipv6,
        Tins::TCP const* tcp,
        Tins::UDP const* udp) -> void override;

    auto advanceTick(timeval now) -> void override;

    [[nodiscard]] auto getProtocol() const -> CollectorProtocol override { return CollectorProtocol::TCP; };
    [[nodiscard]] auto toString() const -> std::string override { return "TcpStatsCollector"; }

    [[nodiscard]] auto getTcpFlow() const { return hashToTcpFlow; }

private:
    typedef std::array<int, 65536> portArray;
    std::unordered_map<FlowId, TcpFlow, std::hash<FlowId>> hashToTcpFlow;
    portArray srvPortsCounter = {};

    std::vector<std::pair<TcpFlow*, std::vector<TcpAggregatedFlow*>>> openingTcpFlow;
    auto lookupTcpFlow(Tins::TCP const& tcpLayer,
        FlowId const& flowId) -> TcpFlow*;
    auto lookupAggregatedFlows(FlowId const& flowId, std::string const& fqdn, Direction srvDir) -> std::vector<TcpAggregatedFlow*>;
    [[nodiscard]] auto detectServer(Tins::TCP const& tcp, FlowId const& flowId) -> Direction;
    [[nodiscard]] auto getSortFun(Field field) const -> sortFlowFun override;

    void timeoutOpeningConnections(timeval now);
    void timeoutFlows(timeval now);

    int lastTick = 0;
    IpToFqdn* ipToFqdn;
};
} // namespace flowstats
