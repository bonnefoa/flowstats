#pragma once
#include "Utils.hpp"
#include <arpa/inet.h>
#include <ip.h>
#include <sstream>
#include <stdint.h>
#include <tcp.h>
#include <udp.h>

namespace flowstats {

using Port = uint16_t;
using IPv4 = uint32_t;

struct FlowId {
    Tins::IPv4Address ips[2] = { Tins::IPv4Address((uint32_t)0),
        Tins::IPv4Address((uint32_t)0) };
    Port ports[2] = { 0, 0 };
    bool isTcp = false;
    Direction direction;

    FlowId() {}
    FlowId(uint16_t ports[2], IPv4 pktIps[2], bool isTcp);
    FlowId(Tins::IP* ipv4Layer, Tins::TCP* tcpLayer);
    FlowId(Tins::IP* ipv4Layer, Tins::UDP* udpLayer);
    FlowId(Tins::Packet& packet);

    std::string toString();
};
}

namespace std {

template <>
struct hash<flowstats::FlowId> {
    size_t operator()(const flowstats::FlowId& flowId) const
    {
        return std::hash<Tins::IPv4Address>()(flowId.ips[0]) + std::hash<Tins::IPv4Address>()(flowId.ips[1]) + std::hash<uint16_t>()(flowId.ports[0]) + std::hash<uint16_t>()(flowId.ports[1]);
        //+ std::hash<std::underlying_type<flowstats::Direction>::type>()(flowId.direction);
    }
};

} // std
