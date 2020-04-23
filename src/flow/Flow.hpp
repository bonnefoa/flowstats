#pragma once

#include "FlowId.hpp"
#include <map>
#include <packet.h>

namespace flowstats {

class Flow {

public:
    FlowId flowId;
    uint8_t srvPos = 1;
    timeval start = {};
    timeval end = {};

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

    Flow(Tins::Packet& packet)
        : flowId(packet)
    {
        Flow();
    }

    Flow(const Tins::IP& ipv4, const Tins::TCP& tcp)
        : flowId(ipv4, tcp)
    {
        Flow();
    }

    Flow(const Tins::IP& ipv4, const Tins::UDP& udp)
        : flowId(ipv4, udp)
    {
        Flow();
    }

    Flow(const FlowId& flowId, const std::string fqdn)
        : flowId(flowId)
        , fqdn(fqdn)
    {
    }

    bool operator<(const Flow& flow) const
    {
        return (bytes[0] + bytes[1]) < (flow.bytes[0] + flow.bytes[1]);
    }

    uint16_t getSrvPort();
    Tins::IPv4Address getSrvIp();
    Tins::IPv4Address getCltIp();
    IPv4 getCltIpInt();
    IPv4 getSrvIpInt();

    void addPacket(Tins::Packet& packet, const Direction direction);
    virtual void addFlow(Flow* flow);
    virtual void addAggregatedFlow(Flow* flow);
    virtual void resetFlow(bool resetTotal);
    virtual void fillValues(std::map<std::string, std::string>& map,
        Direction direction, int duration);
};
}
