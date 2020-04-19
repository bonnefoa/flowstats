#include "AggregatedFlow.hpp"

namespace flowstats {

auto caseInsensitiveComp(char c1, char  /*c2*/) -> bool
{
    return std::tolower(c1) < std::tolower(c1);
}

auto sortAggregatedPairByFqdn(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    std::string s1 = left.second->fqdn;
    std::string s2 = right.second->fqdn;
    return std::lexicographical_compare(
        s1.begin(), s1.end(), s2.begin(), s2.end(), caseInsensitiveComp);
}

auto sortAggregatedPairByByte(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    return (right.second->totalBytes[0] + right.second->totalBytes[1])
        < (left.second->totalBytes[0] + left.second->totalBytes[1]);
}

auto sortAggregatedPairByPacket(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    return (right.second->totalPackets[0] + right.second->totalPackets[1])
        < (left.second->totalPackets[0] + left.second->totalPackets[1]);
}
} // namespace flowstats
