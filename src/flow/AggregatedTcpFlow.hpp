#pragma once

#include "AggregatedFlow.hpp"
#include "AggregatedKeys.hpp"
#include "Field.hpp"
#include "Flow.hpp"
#include "Stats.hpp"
#include <map>
#include <spdlog/spdlog.h>

namespace flowstats {

struct AggregatedTcpFlow : Flow {
    AggregatedTcpFlow()
        : Flow("Total") {};

    AggregatedTcpFlow(FlowId const& flowId, std::string const& fqdn)
        : Flow(flowId, fqdn) {};

    AggregatedTcpFlow(FlowId const& flowId, std::string const& fqdn, uint8_t srvDir)
        : Flow(flowId, fqdn, srvDir) {};

    ~AggregatedTcpFlow() override;

    auto operator<(AggregatedTcpFlow const& b) const -> bool
    {
        return syns[0] < b.syns[0];
    }

    auto updateFlow(Tins::Packet const& packet, FlowId const& flowId,
        Tins::TCP const& tcpLayer) -> void;

    auto resetFlow(bool resetTotal) -> void override;
    auto fillValues(std::map<Field, std::string>& map,
        Direction direction, int duration) const -> void override;
    auto addAggregatedFlow(Flow const* flow) -> void override;

    auto mergePercentiles() -> void override;
    auto failConnection() -> void;
    auto closeConnection() -> void;
    auto openConnection(int connectionTime) -> void;
    auto ongoingConnection() -> void;
    auto addSrt(int srt, int dataSize) -> void;
    auto getStatsdMetrics() const -> std::vector<std::string> override;

    [[nodiscard]] static auto sortBySrt(Flow const* a, Flow const* b) -> bool
    {
        auto aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->srts.getPercentile(1.0) < bCast->srts.getPercentile(1.0);
    }

    [[nodiscard]] static auto sortByRequest(Flow const* a, Flow const* b) -> bool
    {
        auto aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->totalSrts < bCast->totalSrts;
    }

    [[nodiscard]] static auto sortByRequestRate(Flow const* a, Flow const* b) -> bool
    {
        auto aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->srts.getCount() < bCast->srts.getCount();
    }

    [[nodiscard]] static auto sortBySyn(Flow const* a, Flow const* b) -> bool
    {
        auto aCast = static_cast<AggregatedTcpFlow const*>(a);
        auto bCast = static_cast<AggregatedTcpFlow const*>(b);
        return aCast->syns < bCast->syns;
    }

private:
    std::array<int, 2> syns = {};
    std::array<int, 2> synacks = {};
    std::array<int, 2> fins = {};
    std::array<int, 2> rsts = {};
    std::array<int, 2> zeroWins = {};
    std::array<uint32_t, 2> mtu = {};

    int closes = 0;
    int totalCloses = 0;

    int activeConnections = 0;

    int failedConnections = 0;

    int numConnections = 0;
    int totalConnections = 0;

    int numSrts = 0;
    int totalSrts = 0;

    Percentile connections;
    Percentile srts;
    Percentile requestSizes;
};

} // namespace flowstats
