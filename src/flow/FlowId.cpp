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

FlowId::FlowId(FlowId const&& flowId) noexcept
{
    transport = flowId.transport;
    direction = flowId.direction;
    ips = flowId.ips;
    ports = flowId.ports;
}

FlowId::FlowId(FlowId const& flowId)
{
    *this = flowId;
}

auto FlowId::operator=(FlowId const& flowId) -> FlowId&
{
    if (this == &flowId) {
        return *this;
    }
    transport = flowId.transport;
    direction = flowId.direction;
    ips[0] = flowId.ips[0];
    ips[1] = flowId.ips[1];
    ports[0] = flowId.ports[0];
    ports[1] = flowId.ports[1];
    return *this;
}

FlowId::FlowId(Tins::Packet const& packet)
{
    auto ip = packet.pdu()->find_pdu<Tins::IP>();
    if (ip == nullptr) {
        return;
    }
    try {
        auto tcp = ip->find_pdu<Tins::TCP>();
        if (tcp == nullptr) {
            return;
        }
        *this = FlowId(*ip, *tcp);
        return;
    } catch (Tins::pdu_not_found const&) {
        auto udp = ip->find_pdu<Tins::UDP>();
        if (udp == nullptr) {
            return;
        }
        *this = FlowId(*ip, *udp);
    }
}

FlowId::FlowId(std::array<uint16_t, 2> pktPorts, std::array<IPv4, 2> pktIps, Transport transport)
    : transport(transport)
{
    if (pktPorts[0] < pktPorts[1]) {
        direction = FROM_SERVER;
    }
    ips[0] = Tins::IPv4Address(pktIps[0 + direction]);
    ips[1] = Tins::IPv4Address(pktIps[1 - direction]);
    ports[0] = pktPorts[0 + direction];
    ports[1] = pktPorts[1 - direction];
}

auto FlowId::toString() const -> std::string
{
    return fmt::format("{}:{} -> {}:{}",
        Tins::IPv4Address(ips[direction]).to_string(), ports[direction],
        Tins::IPv4Address(ips[!direction]).to_string(), ports[!direction]);
}
} // namespace flowstats
