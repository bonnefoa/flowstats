#include "AggregatedFlow.hpp"

namespace flowstats {

auto sortAggregatedPairByFqdn(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    return left.second->sortByFqdn(*right.second);
}

auto sortAggregatedPairByByte(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    return left.second->sortByTotalBytes(*right.second);
}

auto sortAggregatedPairByPacket(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    return left.second->sortByPackets(*right.second);
}

} // namespace flowstats
