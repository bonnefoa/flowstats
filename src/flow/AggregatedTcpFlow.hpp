#pragma once

#include "AggregatedKeys.hpp"
#include "Field.hpp"
#include "Flow.hpp"
#include "Stats.hpp"
#include <map>

namespace flowstats {

class TrafficStats {
public:
    uint64_t bytes = 0;
    uint64_t pkts = 0;

    enum TrafficType {
        BYTES,
        PKTS,
    };

};

class AggregatedTcpFlow : public Flow {
public:
    AggregatedTcpFlow()
        : Flow("Total") {};

    AggregatedTcpFlow(FlowId const& flowId, std::string const& fqdn)
        : Flow(flowId, fqdn) {};

    AggregatedTcpFlow(FlowId const& flowId, std::string const& fqdn, uint8_t srvDir)
        : Flow(flowId, fqdn, srvDir) {};

    ~AggregatedTcpFlow() override;

    auto operator<(AggregatedTcpFlow const& b) const -> bool
    {
        return totalSyns[0] < b.totalSyns[0];
    }

    auto updateFlow(Tins::Packet const& packet,
        FlowId const& flowId,
        Tins::TCP const& tcpLayer) -> void;

    auto resetFlow(bool resetTotal) -> void override;

    auto addAggregatedFlow(Flow const* flow) -> void override;

    auto mergePercentiles() -> void override;
    auto failConnection() -> void;
    auto closeConnection() -> void;
    auto addCltPacket(IPAddress const& ipClt, int numBytes) -> void;
    auto openConnection(int connectionTime) -> void;
    auto ongoingConnection() -> void;
    auto addSrt(int srt, int dataSize) -> void;

    [[nodiscard]] auto getFieldStr(Field field, Direction direction, int duration) const -> std::string override;
    [[nodiscard]] auto getStatsdMetrics() const -> std::vector<std::string> override;

    [[nodiscard]] static auto sortByMtu(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->mtu[0] + aCast->mtu[1] < bCast->mtu[0] + bCast->mtu[1];
    }

    [[nodiscard]] static auto sortBySrt(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->numSrts < bCast->numSrts;
    }

    [[nodiscard]] static auto sortBySrtRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->srts.getCount() < bCast->srts.getCount();
    }

    [[nodiscard]] static auto sortByRequest(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalNumSrts < bCast->totalNumSrts;
    }

    [[nodiscard]] static auto sortByRequestRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->srts.getCount() < bCast->srts.getCount();
    }

    [[nodiscard]] static auto sortBySyn(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalSyns < bCast->totalSyns;
    }

    [[nodiscard]] static auto sortBySynRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->syns < bCast->syns;
    }

    [[nodiscard]] static auto sortBySynAck(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalSynAcks < bCast->totalSynAcks;
    }

    [[nodiscard]] static auto sortBySynAckRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->synAcks < bCast->synAcks;
    }

    [[nodiscard]] static auto sortByZwin(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalZeroWins < bCast->totalZeroWins;
    }

    [[nodiscard]] static auto sortByZwinRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->zeroWins < bCast->zeroWins;
    }

    [[nodiscard]] static auto sortByRst(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalRsts < bCast->totalRsts;
    }

    [[nodiscard]] static auto sortByRstRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->rsts < bCast->rsts;
    }

    [[nodiscard]] static auto sortByFin(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalFins < bCast->totalFins;
    }

    [[nodiscard]] static auto sortByFinRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->fins < bCast->fins;
    }

    [[nodiscard]] static auto sortByActiveConnections(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->activeConnections < bCast->activeConnections;
    }

    [[nodiscard]] static auto sortByFailedConnections(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->failedConnections < bCast->failedConnections;
    }

    [[nodiscard]] static auto sortByConnectionRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->numConnections < bCast->numConnections;
    }

    [[nodiscard]] static auto sortByConnections(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalConnections < bCast->totalConnections;
    }

    [[nodiscard]] static auto sortByCtP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->connectionTimes.getPercentile(0.95) < bCast->connectionTimes.getPercentile(0.95);
    }

    [[nodiscard]] static auto sortByCtTotalP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalConnectionTimes.getPercentile(0.95) < bCast->totalConnectionTimes.getPercentile(0.95);
    }

    [[nodiscard]] static auto sortByCtP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->connectionTimes.getPercentile(0.99) < bCast->connectionTimes.getPercentile(0.99);
    }

    [[nodiscard]] static auto sortByCtTotalP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalConnectionTimes.getPercentile(0.99) < bCast->totalConnectionTimes.getPercentile(0.99);
    }

    [[nodiscard]] static auto sortByCtMax(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->connectionTimes.getPercentile(1) < bCast->connectionTimes.getPercentile(1);
    }

    [[nodiscard]] static auto sortByCtTotalMax(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalConnectionTimes.getPercentile(1) < bCast->totalConnectionTimes.getPercentile(1);
    }

    [[nodiscard]] static auto sortBySrtP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->srts.getPercentile(0.95) < bCast->srts.getPercentile(0.95);
    }

    [[nodiscard]] static auto sortBySrtTotalP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalSrts.getPercentile(0.95) < bCast->totalSrts.getPercentile(0.95);
    }

    [[nodiscard]] static auto sortBySrtP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->srts.getPercentile(0.99) < bCast->srts.getPercentile(0.99);
    }

    [[nodiscard]] static auto sortBySrtTotalP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalSrts.getPercentile(0.99) < bCast->totalSrts.getPercentile(0.99);
    }

    [[nodiscard]] static auto sortBySrtMax(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->srts.getPercentile(1) < bCast->srts.getPercentile(1);
    }

    [[nodiscard]] static auto sortBySrtTotalMax(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalSrts.getPercentile(1) < bCast->totalSrts.getPercentile(1);
    }

    [[nodiscard]] static auto sortByDsP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->requestSizes.getPercentile(0.95) < bCast->requestSizes.getPercentile(0.95);
    }

    [[nodiscard]] static auto sortByDsTotalP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalRequestSizes.getPercentile(0.95) < bCast->totalRequestSizes.getPercentile(0.95);
    }

    [[nodiscard]] static auto sortByDsP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->requestSizes.getPercentile(0.99) < bCast->requestSizes.getPercentile(0.99);
    }

    [[nodiscard]] static auto sortByDsTotalP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalRequestSizes.getPercentile(0.99) < bCast->totalRequestSizes.getPercentile(0.99);
    }

    [[nodiscard]] static auto sortByDsMax(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->requestSizes.getPercentile(1) < bCast->requestSizes.getPercentile(1);
    }

    [[nodiscard]] static auto sortByDsTotalMax(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalRequestSizes.getPercentile(1) < bCast->totalRequestSizes.getPercentile(1);
    }

    [[nodiscard]] static auto sortByClose(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalCloses < bCast->totalCloses;
    }

    [[nodiscard]] static auto sortByCloseRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto const* bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->closes < bCast->closes;
    }

private:
    [[nodiscard]] auto getTopClientIps(std::map<IPAddress, TrafficStats> const& srcMap, TrafficStats::TrafficType type) const -> std::string;

    std::array<int, 2> syns = {};
    std::array<int, 2> synAcks = {};
    std::array<int, 2> fins = {};
    std::array<int, 2> rsts = {};
    std::array<int, 2> zeroWins = {};

    std::array<int, 2> totalSyns = {};
    std::array<int, 2> totalSynAcks = {};
    std::array<int, 2> totalFins = {};
    std::array<int, 2> totalRsts = {};
    std::array<int, 2> totalZeroWins = {};

    std::array<uint32_t, 2> mtu = {};

    std::map<IPAddress, TrafficStats> sourceIpToStats;

    int closes = 0;
    int totalCloses = 0;

    int activeConnections = 0;
    int failedConnections = 0;

    int numConnections = 0;
    int totalConnections = 0;

    int numSrts = 0;
    int totalNumSrts = 0;

    Percentile connectionTimes;
    Percentile srts;
    Percentile requestSizes;

    Percentile totalConnectionTimes;
    Percentile totalSrts;
    Percentile totalRequestSizes;
};

} // namespace flowstats
