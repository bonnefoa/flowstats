#include "AggregatedFlow.hpp"

namespace flowstats {

auto caseInsensitiveComp(char c1, char c2) -> bool
{
    return std::tolower(c1) < std::tolower(c2);
}

auto sortAggregatedPairByFqdn(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    std::string s1 = left.second->getFqdn();
    std::string s2 = right.second->getFqdn();
    return std::lexicographical_compare(
        s1.begin(), s1.end(), s2.begin(), s2.end(), caseInsensitiveComp);
}

auto sortAggregatedPairByByte(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    auto rightBytes = right.second->getTotalBytes();
    auto leftBytes = left.second->getTotalBytes();
    return (rightBytes[0] + rightBytes[1]) < (leftBytes[0] + leftBytes[1]);
}

auto sortAggregatedPairByPacket(const AggregatedPairPointer& left,
    const AggregatedPairPointer& right) -> bool
{
    auto rightPackets = right.second->getTotalPackets();
    auto leftPackets = left.second->getTotalPackets();
    return (rightPackets[0] + rightPackets[1]) < (leftPackets[0] + leftPackets[1]);
}
} // namespace flowstats
