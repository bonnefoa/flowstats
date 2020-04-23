#include "FlowId.hpp"
#include <fmt/format.h>

namespace flowstats {

auto FlowId::toString() const -> std::string
{
    return fmt::format("{}:{} -> {}:{}",
        Tins::IPv4Address(ips[direction]).to_string(), ports[direction],
        Tins::IPv4Address(ips[!direction]).to_string(), ports[!direction]);
}

FlowId::FlowId(const Tins::IP& ip, const Tins::TCP& tcp)
{
    Port pktPorts[2] = { tcp.sport(), tcp.dport() };
    IPv4 pktIps[2] = { ip.src_addr(), ip.dst_addr() };
    *this = FlowId(pktPorts, pktIps, true);
}

FlowId::FlowId(const Tins::IP& ip, const Tins::UDP& upd)
{
    Port pktPorts[2] = { upd.sport(), upd.dport() };
    IPv4 pktIps[2] = { ip.src_addr(), ip.dst_addr() };
    *this = FlowId(pktPorts, pktIps, false);
}

FlowId::FlowId(const Tins::Packet& packet)
{
    auto ip = packet.pdu()->rfind_pdu<Tins::IP>();
    try {
        auto tcp = ip.rfind_pdu<Tins::TCP>();
        *this = FlowId(ip, tcp);
        return;
    } catch (const Tins::pdu_not_found) {
        auto udp = ip.rfind_pdu<Tins::UDP>();
        *this = FlowId(ip, udp);
    }
}

FlowId::FlowId(uint16_t pktPorts[2], IPv4 pktIps[2], bool _isTcp)
{
    direction = FROM_CLIENT;
    isTcp = _isTcp;
    if (pktPorts[0] < pktPorts[1]) {
        direction = FROM_SERVER;
    }
    ips[0] = Tins::IPv4Address(pktIps[0 + direction]);
    ips[1] = Tins::IPv4Address(pktIps[1 - direction]);
    ports[0] = pktPorts[0 + direction];
    ports[1] = pktPorts[1 - direction];
}
} // namespace flowstats
