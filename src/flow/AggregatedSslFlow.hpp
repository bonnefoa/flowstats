#pragma once

#include "AggregatedFlow.hpp"
#include "Stats.hpp"

namespace flowstats {

class AggregatedSslFlow : public Flow {
public:
    AggregatedSslFlow()
        : Flow("Total") {};

    AggregatedSslFlow(FlowId const& flowId, std::string const& fqdn)
        : Flow(flowId, fqdn) {};

    auto fillValues(std::map<Field, std::string>& map, Direction direction, int duration) const -> void override;
    auto resetFlow(bool resetTotal) -> void override;
    auto setDomain(std::string _domain) -> void { domain = _domain; }
    auto addConnection(int delta) -> void;
    auto merge() -> void { connections.merge(); };

    auto operator<(AggregatedSslFlow const& f) -> bool
    {
        auto const* leftBytes = getBytes();
        auto const* rightBytes = f.getBytes();
        return leftBytes[0] + leftBytes[1] < rightBytes[0] + rightBytes[1];
    }

    [[nodiscard]] auto getDomain() const { return domain; }

private:
    std::string domain;
    int numConnections = 0;
    int totalConnections = 0;
    Percentile connections;
};
} // namespace flowstats
