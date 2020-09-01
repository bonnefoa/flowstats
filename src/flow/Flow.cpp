#include "Flow.hpp"
#include "Utils.hpp"

namespace flowstats {

auto Flow::addPacket(Tins::Packet const& packet,
    Direction const direction) -> void
{
    packets[direction]++;
    bytes[direction] += packet.pdu()->advertised_size();
    totalPackets[direction]++;
    totalBytes[direction] += packet.pdu()->advertised_size();
    auto tv = packetToTimeval(packet);
    if (start.tv_sec == 0) {
        start = tv;
    }
    end = tv;
}

auto Flow::fillValues(std::map<Field, std::string>* ptrValues,
    Direction direction, int duration) const -> void
{
    auto& values = *ptrValues;
    values[Field::PKTS_RATE] = prettyFormatNumber(packets[direction]);
    values[Field::BYTES_RATE] = prettyFormatBytes(bytes[direction]);
    values[Field::PKTS] = prettyFormatNumber(totalPackets[direction]);
    values[Field::BYTES] = prettyFormatBytes(totalBytes[direction]);
    values[Field::DIR] = directionToString(static_cast<Direction>(direction));
}

auto Flow::addFlow(Flow const* flow) -> void
{
    packets[0] += flow->packets[0];
    packets[1] += flow->packets[1];
    totalPackets[0] += flow->totalPackets[0];
    totalPackets[1] += flow->totalPackets[1];

    bytes[0] += flow->bytes[0];
    bytes[1] += flow->bytes[1];
    totalBytes[0] += flow->totalBytes[0];
    totalBytes[1] += flow->totalBytes[1];
}

auto Flow::addAggregatedFlow(Flow const* flow) -> void
{
    addFlow(flow);
}

void Flow::resetFlow(bool resetTotal)
{
    packets[0] = 0;
    packets[1] = 0;
    bytes[0] = 0;
    bytes[1] = 0;

    if (resetTotal) {
        totalPackets[0] = 0;
        totalPackets[1] = 0;
        totalBytes[0] = 0;
        totalBytes[1] = 0;
    }
}
} // namespace flowstats
