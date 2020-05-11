#pragma once

#include "AggregatedFlow.hpp"
#include "Stats.hpp"

namespace flowstats {

struct AggregatedSslFlow : Flow {
    std::string domain;
    int numConnections = 0;
    int totalConnections = 0;
    Percentile connections;

    AggregatedSslFlow()
        : Flow("Total") {};

    AggregatedSslFlow(FlowId const& flowId, std::string const& fqdn)
        : Flow(flowId, fqdn) {};

    auto operator<(AggregatedSslFlow const& f) -> bool
    {
        auto leftBytes = getBytes();
        auto rightBytes = f.getBytes();
        return leftBytes[0] + leftBytes[1] < rightBytes[0] + rightBytes[1];
    }

    auto fillValues(std::map<Field, std::string>& map, Direction direction, int duration) const -> void override;
    auto resetFlow(bool resetTotal) -> void override;
};
} // namespace flowstats
