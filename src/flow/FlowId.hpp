#pragma once
#include "Utils.hpp"
#include <IPv4Layer.h>
#include <Packet.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <arpa/inet.h>
#include <sstream>
#include <stdint.h>

namespace flowstats {

using Port = uint16_t;
using IPv4 = uint32_t;

struct FlowId {
    IPv4 ips[2] = { (uint32_t)0, (uint32_t)0 };
    Port ports[2] = { 0, 0 };
    Direction direction;

    FlowId() {}
    FlowId(uint16_t ports[2], IPv4 pktIps[2]);
    FlowId(pcpp::IPv4Layer* ipv4Layer, pcpp::TcpLayer* tcpLayer);
    FlowId(pcpp::IPv4Layer* ipv4Layer, pcpp::UdpLayer* udpLayer);
    FlowId(pcpp::Packet* packet);

    std::string toString();
};
}
