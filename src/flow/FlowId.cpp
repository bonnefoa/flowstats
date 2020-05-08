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

FlowId::FlowId(Tins::Packet const& packet)
{
    auto ip = packet.pdu()->rfind_pdu<Tins::IP>();
    try {
        auto tcp = ip.rfind_pdu<Tins::TCP>();
        *this = FlowId(ip, tcp);
        return;
    } catch (Tins::pdu_not_found const&) {
        auto udp = ip.rfind_pdu<Tins::UDP>();
        *this = FlowId(ip, udp);
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
