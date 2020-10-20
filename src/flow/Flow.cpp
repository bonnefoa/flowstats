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

auto Flow::getFieldStr(Field field, Direction direction, int duration, int index) const -> std::string
{
    if (direction == MERGED) {
        switch (field) {
            case Field::PKTS:
                return prettyFormatNumber(totalPackets[FROM_CLIENT] + totalPackets[FROM_SERVER]);
            case Field::PKTS_RATE:
                return prettyFormatNumber(packets[FROM_CLIENT] + packets[FROM_SERVER]);
            case Field::PKTS_AVG:
                return prettyFormatNumberAverage(totalPackets[FROM_CLIENT] + totalPackets[FROM_SERVER], duration);
            case Field::BYTES:
                return prettyFormatBytes(totalBytes[FROM_CLIENT] + totalBytes[FROM_SERVER]);
            case Field::BYTES_RATE:
                return prettyFormatBytes(bytes[FROM_CLIENT] + bytes[FROM_SERVER]);
            case Field::BYTES_AVG:
                return prettyFormatBytesAverage(totalBytes[FROM_CLIENT] + totalBytes[FROM_SERVER], duration);
            default:
                return "";
        }
    }
    switch (field) {
        case Field::PKTS:
            return prettyFormatNumber(totalPackets[direction]);
        case Field::PKTS_RATE:
            return prettyFormatNumber(packets[direction]);
        case Field::PKTS_AVG:
            return prettyFormatNumberAverage(totalPackets[direction], duration);
        case Field::BYTES:
            return prettyFormatBytes(totalBytes[direction]);
        case Field::BYTES_RATE:
            return prettyFormatBytes(bytes[direction]);
        case Field::BYTES_AVG:
            return prettyFormatBytesAverage(totalBytes[direction], duration);
        case Field::DIR:
            return directionToString(static_cast<Direction>(direction));
        default:
            return "";
    }
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
