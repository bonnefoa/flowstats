#pragma once

#include "FlowId.hpp"
#include <map>

namespace flowstats {

class Flow {

public:
    FlowId flowId;
    uint8_t srvPos = 1;
    timespec start = {};
    timespec end = {};

    int packets[2] = {};
    int bytes[2] = {};
    int totalPackets[2] = {};
    int totalBytes[2] = {};
    std::string fqdn;

    Flow()
        : flowId()
    {
    }
    virtual ~Flow() {}

    Flow(pcpp::Packet* packet)
        : flowId(packet)
    {
        Flow();
    }

    Flow(pcpp::IPv4Layer* ipv4Layer, pcpp::TcpLayer* tcpLayer)
        : flowId(ipv4Layer, tcpLayer)
    {
        Flow();
    }

    Flow(pcpp::IPv4Layer* ipv4Layer, pcpp::UdpLayer* udpLayer)
        : flowId(ipv4Layer, udpLayer)
    {
        Flow();
    }

    Flow(FlowId& flowId, std::string fqdn)
        : flowId(flowId)
        , fqdn(fqdn)
    {
    }

    bool operator<(const Flow& flow) const
    {
        return (bytes[0] + bytes[1]) < (flow.bytes[0] + flow.bytes[1]);
    }

    uint16_t getSrvPort();
    pcpp::IPv4Address getSrvIp();
    pcpp::IPv4Address getCltIp();
    IPv4 getCltIpInt();
    IPv4 getSrvIpInt();

    void addPacket(pcpp::Packet* packet, const Direction direction);
    virtual void addFlow(Flow* flow);
    virtual void addAggregatedFlow(Flow* flow);
    virtual void resetFlow(bool resetTotal);
    virtual void fillValues(std::map<std::string, std::string>& map,
        Direction direction, int duration);
};
}
