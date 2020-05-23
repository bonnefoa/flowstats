#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Collector.hpp"
#include "IpToFqdn.hpp"
#include "TcpFlow.hpp"

namespace flowstats {

class TcpStatsCollector : public Collector {
public:
    TcpStatsCollector(FlowstatsConfiguration const& conf,
        DisplayConfiguration const& displayConf,
        IpToFqdn* ipToFqdn);

    auto processPacket(Tins::Packet const& packet,
        FlowId const& flowId,
        Tins::IP const& ip,
        Tins::TCP const* tcp,
        Tins::UDP const* udp) -> void override;

    auto advanceTick(timeval now) -> void override;

    auto getProtocol() const -> CollectorProtocol override { return TCP; };
    auto toString() const -> std::string override { return "TcpStatsCollector"; }

    [[nodiscard]] auto getTcpFlow() const { return hashToTcpFlow; }

private:
    typedef std::array<int, 65536> portArray;
    std::map<size_t, TcpFlow> hashToTcpFlow;
    portArray srvPortsCounter;

    std::vector<std::pair<TcpFlow*, std::vector<AggregatedTcpFlow*>>> openingTcpFlow;
    auto lookupTcpFlow(Tins::IP const& ipv4Layer,
        Tins::TCP const& tcpLayer,
        FlowId const& flowId) -> TcpFlow*;
    auto lookupAggregatedFlows(FlowId const& flowId, std::string const& fqdn, Direction srvDir) -> std::vector<AggregatedTcpFlow*>;
    auto detectServer(Tins::TCP const& tcp, FlowId const& flowId, portArray& srvPortsCounter) -> Direction;
    auto getSortFun(Field field) const -> sortFlowFun override;

    void timeoutOpeningConnections(timeval now);
    void timeoutFlows(timeval now);

    int lastTick = 0;
    IpToFqdn* ipToFqdn;
};
} // namespace flowstats
