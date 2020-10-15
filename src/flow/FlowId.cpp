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

    if (ipv6) {
        std::array<IPv6, 2> pktIps = { ipv6->src_addr(), ipv6->dst_addr() };
        *this = FlowId(pktPorts, pktIps, Network::IPV6, transport);
    } else {
        std::array<IPv4, 2> pktIps = { ip->src_addr(), ip->dst_addr() };
        *this = FlowId(pktPorts, pktIps, Network::IPV4, transport);
    }
}

FlowId::FlowId(Tins::IPv6 const& ip, Tins::TCP const& tcp)
{
    std::array<Port, 2> pktPorts = { tcp.sport(), tcp.dport() };
    std::array<IPv6, 2> pktIps = { ip.src_addr(), ip.dst_addr() };
    *this = FlowId(pktPorts, pktIps, Network::IPV6, Transport::TCP);
}

FlowId::FlowId(Tins::IP const& ip, Tins::TCP const& tcp)
{
    std::array<Port, 2> pktPorts = { tcp.sport(), tcp.dport() };
    std::array<IPv4, 2> pktIps = { ip.src_addr(), ip.dst_addr() };
    *this = FlowId(pktPorts, pktIps, Network::IPV4, Transport::TCP);
}

FlowId::FlowId(Tins::IPv6 const& ip, Tins::UDP const& udp)
{
    std::array<Port, 2> pktPorts = { udp.sport(), udp.dport() };
    std::array<IPv6, 2> pktIps = { ip.src_addr(), ip.dst_addr() };
    *this = FlowId(pktPorts, pktIps, Network::IPV6, Transport::UDP);
}

FlowId::FlowId(Tins::IP const& ip, Tins::UDP const& udp)
{
    std::array<Port, 2> pktPorts = { udp.sport(), udp.dport() };
    std::array<IPv4, 2> pktIps = { ip.src_addr(), ip.dst_addr() };
    *this = FlowId(pktPorts, pktIps, Network::IPV4, Transport::UDP);
}

FlowId::FlowId(FlowId&& flowId) noexcept
{
    transport = flowId.transport;
    network = flowId.network;
    direction = flowId.direction;
    ip.ipv6 = flowId.ip.ipv6;
    ports = flowId.ports;
}

auto FlowId::operator=(FlowId&& flowId) noexcept -> FlowId&
{
    if (this == &flowId) {
        return *this;
    }
    transport = flowId.transport;
    network = flowId.network;
    direction = flowId.direction;
    ip = flowId.ip;
    ports = flowId.ports;
    return *this;
}

auto FlowId::operator=(FlowId const& flowId) noexcept -> FlowId&
{
    transport = flowId.transport;
    network = flowId.network;
    direction = flowId.direction;
    ip = flowId.ip;
    ports[0] = flowId.ports[0];
    ports[1] = flowId.ports[1];
    return *this;
}

FlowId::FlowId(FlowId const& flowId)
{
    *this = flowId;
}

FlowId::FlowId(std::array<uint16_t, 2> pktPorts,
    std::array<IPv4, 2> pktIps,
    Network network, Transport transport)
    : network(network)
    , transport(transport)
{
    if (pktPorts[0] < pktPorts[1]) {
        direction = FROM_SERVER;
    }
    ip.ipv4[0] = pktIps[0 + direction];
    ip.ipv4[1] = pktIps[1 - direction];
    ports[0] = pktPorts[0 + direction];
    ports[1] = pktPorts[1 - direction];
}

FlowId::FlowId(std::array<uint16_t, 2> pktPorts,
    std::array<IPv6, 2> pktIps,
    Network network, Transport transport)
    : network(network)
    , transport(transport)
{
    if (pktPorts[0] < pktPorts[1]) {
        direction = FROM_SERVER;
    }
    ip.ipv6[0] = pktIps[0 + direction];
    ip.ipv6[1] = pktIps[1 - direction];
    ports[0] = pktPorts[0 + direction];
    ports[1] = pktPorts[1 - direction];
}

auto FlowId::toString() const -> std::string
{
    if (network == +Network::IPV4) {
        return fmt::format("{}:{} -> {}:{}",
            ipv4ToString(ip.ipv4[direction]), ports[direction],
            ipv4ToString(ip.ipv4[!direction]), ports[!direction]);
    }
    return "";
}
} // namespace flowstats
