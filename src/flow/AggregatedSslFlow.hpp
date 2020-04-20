#pragma once

#include "AggregatedFlow.hpp"
#include "Stats.hpp"

namespace flowstats {

struct AggregatedSslFlow : Flow {
    std::string domain;
    int numConnections = 0;
    int totalConnections = 0;
    Percentile connections;
    int tickets[2] = { 0, 0 };

    AggregatedSslFlow() { fqdn = "Total"; };
    AggregatedSslFlow(FlowId& _flowId, std::string _fqdn)
        : Flow(_flowId, _fqdn) {};

    bool operator<(AggregatedSslFlow const& f)
    {
        return bytes[0] + bytes[1] < f.bytes[0] + f.bytes[1];
    }

    void fillValues(std::map<std::string, std::string>& map, Direction direction, int duration);
    void resetFlow(bool resetTotal);
};
}
