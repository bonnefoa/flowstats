#pragma once

#include "AggregatedFlow.hpp"
#include "Stats.hpp"

namespace flowstats {

struct AggregatedSslFlow : Flow {
    std::string domain;
    int numConnections = 0;
    int totalConnections = 0;
    Percentile connections;

    AggregatedSslFlow() { fqdn = "Total"; };
    AggregatedSslFlow(FlowId const& flowId, std::string const& fqdn)
        : Flow(flowId, fqdn) {};

    auto operator<(AggregatedSslFlow const& f) -> bool
    {
        return bytes[0] + bytes[1] < f.bytes[0] + f.bytes[1];
    }

    auto fillValues(std::map<std::string, std::string>& map, Direction direction, int duration) const -> void override;
    auto resetFlow(bool resetTotal) -> void override;
};
} // namespace flowstats
