#pragma once

#include "AggregatedFlow.hpp"
#include "Flow.hpp"
#include "Stats.hpp"
#include <map>
#include <spdlog/spdlog.h>

namespace flowstats {

struct AggregatedTcpFlow : Flow {
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

    AggregatedTcpFlow()
    {
        fqdn = "Total";
    };

    AggregatedTcpFlow(FlowId& flowId, std::string fqdn)
        : Flow(flowId, fqdn) {};

    bool operator<(AggregatedTcpFlow const& b) const
    {
        return syns[0] < b.syns[0];
    }

    void updateFlow(const Tins::PtrPacket& packet, const FlowId& flowId,
        const Tins::TCP* tcpLayer);

    void resetFlow(bool resetTotal);
    void fillValues(std::map<std::string, std::string>& map, Direction direction, int duration);
};
}
