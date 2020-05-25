#include "FlowId.hpp"
#include <fmt/format.h>

namespace flowstats {

FlowId::FlowId(Tins::IP const& ip, Tins::TCP const& tcp)
{
    std::array<Port, 2> pktPorts = { tcp.sport(), tcp.dport() };
    std::array<IPv4, 2> pktIps = { ip.src_addr(), ip.dst_addr() };
    *this = FlowId(pktPorts, pktIps, Transport::TCP);
}

FlowId::FlowId(Tins::IP const& ip, Tins::UDP const& udp)
{
    std::array<Port, 2> pktPorts = { udp.sport(), udp.dport() };
    std::array<IPv4, 2> pktIps = { ip.src_addr(), ip.dst_addr() };
    *this = FlowId(pktPorts, pktIps, Transport::UDP);
}

FlowId::FlowId(FlowId&& flowId) noexcept
{
    transport = flowId.transport;
    direction = flowId.direction;
    ips = flowId.ips;
    ports = flowId.ports;
}

auto FlowId::operator=(FlowId&& flowId) noexcept -> FlowId&
{
    if (this == &flowId) {
        return *this;
    }
    transport = flowId.transport;
    direction = flowId.direction;
    ips = flowId.ips;
    ports = flowId.ports;
    return *this;
}

auto FlowId::operator=(FlowId const& flowId) noexcept -> FlowId&
{
    transport = flowId.transport;
    direction = flowId.direction;
    ips[0] = flowId.ips[0];
    ips[1] = flowId.ips[1];
    ports[0] = flowId.ports[0];
    ports[1] = flowId.ports[1];
    return *this;
}

FlowId::FlowId(FlowId const& flowId)
{
    *this = flowId;
}

FlowId::FlowId(std::array<uint16_t, 2> pktPorts, std::array<IPv4, 2> pktIps, Transport transport)
    : transport(transport)
{
    if (pktPorts[0] < pktPorts[1]) {
        direction = FROM_SERVER;
    }
    ips[0] = pktIps[0 + direction];
    ips[1] = pktIps[1 - direction];
    ports[0] = pktPorts[0 + direction];
    ports[1] = pktPorts[1 - direction];
}

auto FlowId::toString() const -> std::string
{
    return fmt::format("{}:{} -> {}:{}",
        ipv4ToString(ips[direction]), ports[direction],
        ipv4ToString(ips[!direction]), ports[!direction]);
}
} // namespace flowstats
