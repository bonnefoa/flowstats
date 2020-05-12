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

    AggregatedTcpFlow(FlowId const& flowId, std::string fqdn)
        : Flow(flowId, fqdn) {};

    auto operator<(AggregatedTcpFlow const& b) const -> bool
    {
        return syns[0] < b.syns[0];
    }

    auto updateFlow(Tins::Packet const& packet, FlowId const& flowId,
        Tins::TCP const& tcpLayer) -> void;

    auto resetFlow(bool resetTotal) -> void;
    auto fillValues(std::map<Field, std::string>& map,
        Direction direction, int duration) const -> void;

    auto mergePercentiles() -> void;
    auto failConnection() -> void;
    auto closeConnection() -> void;
    auto openConnection(int connectionTime) -> void;
    auto ongoingConnection() -> void;
    auto addSrt(int srt, int dataSize) -> void;
    auto getMetrics(std::vector<std::string> lst) const -> void;

    auto sortBySrt(AggregatedTcpFlow const& b) const -> bool
    {
        return srts.getPercentile(1.0) < b.srts.getPercentile(1.0);
    }

    auto sortByRequest(AggregatedTcpFlow const& b) const -> bool
    {
        return totalSrts < b.totalSrts;
    }

    auto sortByRequestRate(AggregatedTcpFlow const& b) const -> bool
    {
        return srts.getCount() < b.srts.getCount();
    }

private:
    int syns[2] = {};
    int synacks[2] = {};
    int fins[2] = {};
    int rsts[2] = {};
    int zeroWins[2] = {};
    uint32_t mtu[2] = {};

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
