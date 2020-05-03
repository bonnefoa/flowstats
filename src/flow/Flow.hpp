#pragma once

#include "FlowId.hpp"
#include <map>
#include <tins/packet.h>

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

    Flow(Tins::Packet const& packet)
        : flowId(packet)
    {
        Flow();
    }

    Flow(Tins::IP const& ipv4, Tins::TCP const& tcp)
        : flowId(ipv4, tcp)
    {
        Flow();
    }

    Flow(Tins::IP const& ipv4, Tins::UDP const& udp)
        : flowId(ipv4, udp)
    {
        Flow();
    }

    Flow(FlowId const& flowId, std::string const& fqdn)
        : flowId(flowId)
        , fqdn(fqdn)
    {
    }

    bool operator<(Flow const& flow) const
    {
        return (bytes[0] + bytes[1]) < (flow.bytes[0] + flow.bytes[1]);
    }

    auto getSrvPort() const -> uint16_t;
    auto getSrvIp() const -> Tins::IPv4Address;
    auto getCltIp() const -> Tins::IPv4Address;
    auto getCltIpInt() const -> IPv4;
    auto getSrvIpInt() const -> IPv4;

    auto addPacket(Tins::Packet const& packet, Direction const direction) -> void;
    virtual auto addFlow(Flow const* flow) -> void;
    virtual auto addAggregatedFlow(Flow const* flow) -> void;
    virtual auto resetFlow(bool resetTotal) -> void;
    virtual auto fillValues(std::map<std::string, std::string>& map,
        Direction direction, int duration) -> void;
};
}
