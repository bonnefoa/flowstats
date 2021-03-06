#pragma once

#include "AggregatedKeys.hpp"
#include "Field.hpp"
#include "Flow.hpp"
#include "Stats.hpp"
#include <map>

namespace flowstats {

class TrafficStatsTcp {
public:
    uint64_t bytes = 0;
    uint64_t pkts = 0;

    enum TrafficType {
        BYTES,
        PKTS,
    };
};

class TcpAggregatedFlow : public Flow {
public:
    TcpAggregatedFlow()
        : Flow("Total") {};

    TcpAggregatedFlow(FlowId const& flowId, std::string const& fqdn)
        : Flow(flowId, fqdn) {};

    TcpAggregatedFlow(FlowId const& flowId, std::string const& fqdn, uint8_t srvDir)
        : Flow(flowId, fqdn, srvDir) {};

    ~TcpAggregatedFlow() override;

    auto operator<(TcpAggregatedFlow const& b) const -> bool
    {
        return totalSyns[0] < b.totalSyns[0];
    }

    auto updateFlow(Tins::Packet const& packet,
        FlowId const& flowId,
        Tins::TCP const& tcpLayer) -> void;

    auto resetFlow(bool resetTotal) -> void override;
    auto addAggregatedFlow(Flow const* flow) -> void override;
    auto mergePercentiles() -> void override;
    auto prepareSubfields(std::vector<Field> const& fields) -> void override;

    auto failConnection() -> void;
    auto closeConnection() -> void;
    auto addCltPacket(IPAddress const& ipClt, int numBytes) -> void;
    auto openConnection(int connectionTime) -> void;
    auto ongoingConnection() -> void;
    auto addSrt(int srt, int dataSize) -> void;

    [[nodiscard]] auto getFieldStr(Field field, Direction direction, int duration, int index) const -> std::string override;
    [[nodiscard]] auto getSubfieldSize(Field field) const -> int override;

    [[nodiscard]] static auto sortByMtu(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->mtu[0] + aCast->mtu[1] < bCast->mtu[0] + bCast->mtu[1];
    }

    [[nodiscard]] static auto sortBySrt(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->numSrts < bCast->numSrts;
    }

    [[nodiscard]] static auto sortBySrtRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->srts.getCount() < bCast->srts.getCount();
    }

    [[nodiscard]] static auto sortByRequest(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->totalNumSrts < bCast->totalNumSrts;
    }

    [[nodiscard]] static auto sortByRequestRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->srts.getCount() < bCast->srts.getCount();
    }

    [[nodiscard]] static auto sortBySyn(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->totalSyns < bCast->totalSyns;
    }

    [[nodiscard]] static auto sortBySynRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->syns < bCast->syns;
    }

    [[nodiscard]] static auto sortBySynAck(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->totalSynAcks < bCast->totalSynAcks;
    }

    [[nodiscard]] static auto sortBySynAckRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->synAcks < bCast->synAcks;
    }

    [[nodiscard]] static auto sortByZwin(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->totalZeroWins < bCast->totalZeroWins;
    }

    [[nodiscard]] static auto sortByZwinRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->zeroWins < bCast->zeroWins;
    }

    [[nodiscard]] static auto sortByRst(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->totalRsts < bCast->totalRsts;
    }

    [[nodiscard]] static auto sortByRstRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->rsts < bCast->rsts;
    }

    [[nodiscard]] static auto sortByFin(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->totalFins < bCast->totalFins;
    }

    [[nodiscard]] static auto sortByFinRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->fins < bCast->fins;
    }

    [[nodiscard]] static auto sortByActiveConnections(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->activeConnections < bCast->activeConnections;
    }

    [[nodiscard]] static auto sortByFailedConnections(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->failedConnections < bCast->failedConnections;
    }

    [[nodiscard]] static auto sortByConnectionRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->numConnections < bCast->numConnections;
    }

    [[nodiscard]] static auto sortByConnections(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->totalConnections < bCast->totalConnections;
    }

    [[nodiscard]] static auto sortBySrt(Flow const* a, Flow const* b,
            float percentile, bool total) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        auto& aPercentile = total? aCast->totalSrts : aCast->srts;
        auto& bPercentile = total? bCast->totalSrts : bCast->srts;
        return aPercentile.getPercentile(percentile) < bPercentile.getPercentile(percentile);
    }

    [[nodiscard]] static auto sortByCt(Flow const* a, Flow const* b,
            float percentile, bool total) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        auto& aPercentile = total? aCast->totalConnectionTimes : aCast->connectionTimes;
        auto& bPercentile = total? bCast->totalConnectionTimes : bCast->connectionTimes;
        return aPercentile.getPercentile(percentile) < bPercentile.getPercentile(percentile);
    }

    [[nodiscard]] static auto sortByDs(Flow const* a, Flow const* b,
            float percentile, bool total) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        auto& aPercentile = total? aCast->totalRequestSizes : aCast->requestSizes;
        auto& bPercentile = total? bCast->totalRequestSizes : bCast->requestSizes;
        return aPercentile.getPercentile(percentile) < bPercentile.getPercentile(percentile);
    }

    [[nodiscard]] static auto sortByClose(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->totalCloses < bCast->totalCloses;
    }

    [[nodiscard]] static auto sortByCloseRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = static_cast<TcpAggregatedFlow const*>(a);
        auto const* bCast = static_cast<TcpAggregatedFlow const*>(b);
        return aCast->closes < bCast->closes;
    }

private:
    auto computeTopClientIps(TrafficStatsTcp::TrafficType type) -> void;
    [[nodiscard]] auto getTopClientIpsKey(int index) const -> std::string;
    [[nodiscard]] auto getTopClientIpsValue(TrafficStatsTcp::TrafficType type, int index) const -> std::string;
    std::vector<std::pair<IPAddress, TrafficStatsTcp>> topClientIps;

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

    std::map<IPAddress, TrafficStatsTcp> sourceIpToStats;

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
