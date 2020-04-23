#include "FlowId.hpp"
#include <fmt/format.h>

namespace flowstats {

auto FlowId::toString() -> std::string
{
    return fmt::format("{}:{} -> {}:{}",
        Tins::IPv4Address(ips[direction]).to_string(), ports[direction],
        Tins::IPv4Address(ips[!direction]).to_string(), ports[!direction]);
}

FlowId::FlowId(Tins::IP* ip, Tins::TCP* tcp)
{
    Port pktPorts[2] = { tcp->sport(), tcp->dport() };
    IPv4 pktIps[2] = { ip->src_addr(), ip->dst_addr() };
    *this = FlowId(pktPorts, pktIps, true);
}

FlowId::FlowId(Tins::IP* ip, Tins::UDP* upd)
{
    Port pktPorts[2] = { upd->sport(), upd->dport() };
    IPv4 pktIps[2] = { ip->src_addr(), ip->dst_addr() };
    *this = FlowId(pktPorts, pktIps, false);
}

FlowId::FlowId(Tins::Packet& packet)
{
    auto ip = packet.pdu()->find_pdu<Tins::IP>();
    auto tcp = ip->find_pdu<Tins::TCP>();
    if (tcp) {
        *this = FlowId(ip, tcp);
    } else {
        auto udp = ip->find_pdu<Tins::UDP>();
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
