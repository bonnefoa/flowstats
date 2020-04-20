#include "Flow.hpp"
#include "Utils.hpp"
#include <spdlog/spdlog.h>

namespace flowstats {

void Flow::addPacket(Tins::PtrPacket* packet, const Direction direction)
{
    packets[direction]++;
    bytes[direction] += packet->pdu()->advertised_size();
    totalPackets[direction]++;
    totalBytes[direction] += packet->pdu()->advertised_size();
    if (start.tv_sec == 0) {
        start = { packet->timestamp().seconds(), packet->timestamp().microseconds() };
    }
    end = { packet->timestamp().seconds(), packet->timestamp().microseconds() };
}

void Flow::fillValues(std::map<std::string, std::string>& values,
    Direction direction, int duration)
{
    if (duration) {
        values["pkts_s"] = prettyFormatNumber(totalPackets[direction] / duration);
        values["bytes_s"] = prettyFormatBytes(totalBytes[direction] / duration);
    } else {
        values["pkts_s"] = prettyFormatNumber(packets[direction]);
        values["bytes_s"] = prettyFormatBytes(bytes[direction]);
    }
    values["pkts"] = prettyFormatNumber(totalPackets[direction]);
    values["bytes"] = prettyFormatBytes(totalBytes[direction]);
    values["dir"] = directionToString(static_cast<Direction>(direction));
}

void Flow::addFlow(Flow* flow)
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

void Flow::addAggregatedFlow(Flow* flow)
{
    addFlow(flow);
}

auto Flow::getSrvPort() -> uint16_t
{
    return flowId.ports[srvPos];
}

auto Flow::getCltIp() -> Tins::IPv4Address
{
    return flowId.ips[!srvPos];
}

auto Flow::getSrvIp() -> Tins::IPv4Address
{
    return flowId.ips[srvPos];
}

auto Flow::getCltIpInt() -> IPv4
{
    return flowId.ips[!srvPos];
}

auto Flow::getSrvIpInt() -> IPv4
{
    return flowId.ips[srvPos];
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
