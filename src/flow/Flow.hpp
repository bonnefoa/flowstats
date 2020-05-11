#pragma once

#include "Field.hpp"
#include "FlowId.hpp"
#include <map>
#include <tins/packet.h>

namespace flowstats {

class Flow {

public:
    Flow()
        : flowId()
    {
    }

    Flow(Tins::Packet const& packet)
        : flowId(packet)
    {
    }

    Flow(Tins::IP const& ipv4, Tins::TCP const& tcp)
        : flowId(ipv4, tcp)
    {
    }

    Flow(Tins::IP const& ipv4, Tins::UDP const& udp)
        : flowId(ipv4, udp)
    {
    }

    Flow(std::string const& fqdn)
        : fqdn(fqdn)
    {
    }

    Flow(FlowId const& flowId, std::string const& fqdn)
        : flowId(flowId)
        , fqdn(fqdn)
    {
    }

    Flow(FlowId const& flowId)
        : flowId(flowId)
    {
    }

    virtual ~Flow() {}

    bool operator<(Flow const& flow) const
    {
        return (totalBytes[0] + totalBytes[1]) < (flow.totalBytes[0] + flow.totalBytes[1]);
    }

    auto setSrvPos(uint8_t pos) { srvPos = pos; };
    auto setFlowId(FlowId const& _flowId) { flowId = _flowId; };

    auto addPacket(Tins::Packet const& packet, Direction const direction) -> void;
    virtual auto addFlow(Flow const* flow) -> void;
    virtual auto addAggregatedFlow(Flow const* flow) -> void;
    virtual auto resetFlow(bool resetTotal) -> void;
    virtual auto fillValues(std::map<Field, std::string>& map,
        Direction direction, int duration) const -> void;

    [[nodiscard]] auto getFlowId() const { return flowId; };
    [[nodiscard]] auto getFqdn() const { return fqdn; };
    [[nodiscard]] auto getSrvPos() const { return srvPos; }
    [[nodiscard]] auto getBytes() const { return bytes; };
    [[nodiscard]] auto getPackets() const { return packets; };
    [[nodiscard]] auto getTotalBytes() const { return totalBytes; };
    [[nodiscard]] auto getTotalPackets() const { return totalPackets; };

    [[nodiscard]] auto getTransport() const { return flowId.getTransport(); };
    [[nodiscard]] auto getPort(uint8_t pos) const { return flowId.getPort(pos); }
    [[nodiscard]] auto getSrvPort() const { return flowId.getPort(srvPos); }
    [[nodiscard]] auto getSrvIp() const { return flowId.getIp(srvPos); }
    [[nodiscard]] auto getCltIp() const { return flowId.getIp(!srvPos); }
    [[nodiscard]] auto getCltIpInt() const { return flowId.getIp(!srvPos); }
    [[nodiscard]] auto getSrvIpInt() const { return flowId.getIp(srvPos); }

private:
    FlowId flowId;
    uint8_t srvPos = 1;
    timeval start = {};
    timeval end = {};

    int packets[2] = {};
    int bytes[2] = {};
    int totalPackets[2] = {};
    int totalBytes[2] = {};
    std::string fqdn;
};
} // namespace flowstats
