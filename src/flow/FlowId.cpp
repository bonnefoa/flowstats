#include "FlowId.hpp"
#include <fmt/format.h>

namespace flowstats {

FlowId::FlowId(Tins::IP const* ip, Tins::IPv6 const* ipv6,
    Tins::TCP const* tcp, Tins::UDP const* udp)
{
    std::array<Port, 2> pktPorts = {};
    auto transport = Transport::TCP;
    if (tcp) {
        pktPorts = { tcp->sport(), tcp->dport() };
    } else {
        pktPorts = { udp->sport(), udp->dport() };
        transport = Transport::UDP;
    }

    IPAddressPair addresses;
    if (ipv6) {
        addresses = { IPAddress(ipv6->src_addr()), IPAddress(ipv6->dst_addr()) };
    } else {
        addresses = { IPAddress(ip->src_addr()), IPAddress(ip->dst_addr()) };
    }
    *this = FlowId(pktPorts, addresses, transport);
}

FlowId::FlowId(IPAddressPair const& pair, Tins::TCP const& tcp)
{
    std::array<Port, 2> pktPorts = { tcp.sport(), tcp.dport() };
    *this = FlowId(pktPorts, pair, Transport::TCP);
}

FlowId::FlowId(IPAddressPair const& pair, Tins::UDP const& udp)
{
    std::array<Port, 2> pktPorts = { udp.sport(), udp.dport() };
    *this = FlowId(pktPorts, pair, Transport::UDP);
}

FlowId::FlowId(FlowId&& flowId) noexcept
{
    transport = flowId.transport;
    direction = flowId.direction;
    addressPair = flowId.addressPair;
    ports = flowId.ports;
}

auto FlowId::operator=(FlowId&& flowId) noexcept -> FlowId&
{
    if (this == &flowId) {
        return *this;
    }
    transport = flowId.transport;
    direction = flowId.direction;
    addressPair = flowId.addressPair;
    ports = flowId.ports;
    return *this;
}

auto FlowId::operator=(FlowId const& flowId) noexcept -> FlowId&
{
    transport = flowId.transport;
    direction = flowId.direction;
    addressPair = flowId.addressPair;
    ports[0] = flowId.ports[0];
    ports[1] = flowId.ports[1];
    return *this;
}

FlowId::FlowId(FlowId const& flowId)
{
    *this = flowId;
}

FlowId::FlowId(std::array<uint16_t, 2> pktPorts,
    IPAddressPair const& pair,
    Transport transport)
    : transport(transport)
{
    if (pktPorts[0] < pktPorts[1]) {
        direction = FROM_SERVER;
    }
    addressPair[0] = pair[0 + direction];
    addressPair[1] = pair[1 - direction];
    ports[0] = pktPorts[0 + direction];
    ports[1] = pktPorts[1 - direction];
}

auto FlowId::toString() const -> std::string
{
    return fmt::format("{}:{} -> {}:{}",
        addressPair[direction].getAddrStr(), ports[direction],
        addressPair[!direction].getAddrStr(), ports[!direction]);
}
} // namespace flowstats
