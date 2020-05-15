#include "AggregatedFlow.hpp"

namespace flowstats {

typedef bool (Flow::*sortFlowFun)(Flow const&) const;
auto sortAggregated(sortFlowFun sortFlow, AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    auto* rightFlow = right.second;
    auto* leftFlow = left.second;
    if (rightFlow == nullptr || leftFlow == nullptr) {
        return false;
    }
    return (leftFlow->*sortFlow)(*rightFlow);
}

auto sortAggregatedPairByFqdn(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    return sortAggregated(&Flow::sortByFqdn, left, right);
}

auto sortAggregatedPairByByte(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    return sortAggregated(&Flow::sortByTotalBytes, left, right);
}

auto sortAggregatedPairByPacket(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    return sortAggregated(&Flow::sortByPackets, left, right);
}

} // namespace flowstats
