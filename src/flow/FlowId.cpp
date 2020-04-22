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
    Port pktPorts[2] = { ntohs(tcp->sport()), ntohs(tcp->dport()) };
    IPv4 pktIps[2] = { ip->src_addr(), ip->dst_addr() };
    *this = FlowId(pktPorts, pktIps);
}

FlowId::FlowId(Tins::IP* ip, Tins::UDP* upd)
{
    Port pktPorts[2] = { ntohs(upd->sport()), ntohs(upd->dport()) };
    IPv4 pktIps[2] = { ip->src_addr(), ip->dst_addr() };
    *this = FlowId(pktPorts, pktIps);
}

FlowId::FlowId(Tins::PDU* pdu)
{
    auto ip = pdu->find_pdu<Tins::IP>();
    auto tcp = ip->find_pdu<Tins::TCP>();
    if (tcp) {
        *this = FlowId(ip, tcp);
    } else {
        auto udp = ip->find_pdu<Tins::UDP>();
        *this = FlowId(ip, udp);
    }
}

FlowId::FlowId(uint16_t pktPorts[2], IPv4 pktIps[2])
{
    direction = FROM_CLIENT;
    if (pktPorts[0] < pktPorts[1]) {
        direction = FROM_SERVER;
    }
    ips[0] = Tins::IPv4Address(pktIps[0 + direction]);
    ips[1] = Tins::IPv4Address(pktIps[1 - direction]);
    ports[0] = pktPorts[0 + direction];
    ports[1] = pktPorts[1 - direction];
}
} // namespace flowstats
