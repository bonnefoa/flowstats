#include "AggregatedFlow.hpp"

namespace flowstats {

auto sortAggregated(Flow::sortFlowFun sortFlow,
    AggregatedPairPointer const& left,
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

auto sortAggregatedPairByIp(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    return sortAggregated(&Flow::sortByIp, left, right);
}

auto sortAggregatedPairByPort(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    return sortAggregated(&Flow::sortByPort, left, right);
}

auto sortAggregatedPairByBytes(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    return sortAggregated(&Flow::sortByBytes, left, right);
}

auto sortAggregatedPairByTotalBytes(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    return sortAggregated(&Flow::sortByTotalBytes, left, right);
}

auto sortAggregatedPairByPackets(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    return sortAggregated(&Flow::sortByPackets, left, right);
}

auto sortAggregatedPairByTotalPackets(AggregatedPairPointer const& left,
    AggregatedPairPointer const& right) -> bool
{
    return sortAggregated(&Flow::sortByTotalPackets, left, right);
}

} // namespace flowstats
