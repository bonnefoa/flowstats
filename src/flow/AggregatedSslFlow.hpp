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

    auto fillValues(std::map<Field, std::string>& map, Direction direction) const -> void override;
    auto resetFlow(bool resetTotal) -> void override;
    auto setDomain(std::string _domain) -> void { domain = std::move(_domain); }
    auto addConnection(int delta) -> void;
    auto merge() -> void { connections.merge(); };

    [[nodiscard]] auto getDomain() const { return domain; }

    [[nodiscard]] static auto sortByConnections(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedSslFlow const*>(b);
        return aCast->totalConnections < bCast->totalConnections;
    }

    [[nodiscard]] static auto sortByConnectionRate(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedSslFlow const*>(b);
        return aCast->numConnections < bCast->numConnections;
    }

    [[nodiscard]] static auto sortByConnectionP95(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedSslFlow const*>(b);
        return aCast->connections.getPercentile(.95) < bCast->connections.getPercentile(.95);
    }

    [[nodiscard]] static auto sortByConnectionP99(Flow const* a, Flow const* b) -> bool
    {
        auto const* aCast = dynamic_cast<AggregatedSslFlow const*>(a);
        auto const* bCast = dynamic_cast<AggregatedSslFlow const*>(b);
        return aCast->connections.getPercentile(.99) < bCast->connections.getPercentile(.99);
    }

private:
    std::string domain;
    int numConnections = 0;
    int totalConnections = 0;
    Percentile connections;
};
} // namespace flowstats
