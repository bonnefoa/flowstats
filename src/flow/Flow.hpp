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

    explicit Flow(Tins::Packet const& packet)
        : flowId(packet)
    {
    }

    explicit Flow(std::string fqdn)
        : fqdn(std::move(fqdn))
    {
    }

    explicit Flow(FlowId flowId)
        : flowId(std::move(flowId))
    {
    }

    Flow(Tins::IP const& ipv4, Tins::TCP const& tcp, uint8_t srvPos)
        : flowId(ipv4, tcp)
        , srvPos(srvPos)
    {
    }

    Flow(Tins::IP const& ipv4, Tins::UDP const& udp)
        : flowId(ipv4, udp)
    {
    }

    Flow(FlowId flowId, std::string fqdn)
        : flowId(std::move(flowId))
        , fqdn(std::move(fqdn))
    {
    }

    Flow(FlowId flowId, std::string fqdn, uint8_t srvPos)
        : flowId(std::move(flowId))
        , fqdn(std::move(fqdn))
        , srvPos(srvPos)
    {
    }

    virtual ~Flow() = default;

    auto operator<(Flow const& flow) const -> bool
    {
        return (totalBytes[0] + totalBytes[1]) < (flow.totalBytes[0] + flow.totalBytes[1]);
    }

    auto setSrvPos(uint8_t pos) { srvPos = pos; };
    auto setFlowId(FlowId const& _flowId) { flowId = _flowId; };

    virtual auto addPacket(Tins::Packet const& packet,
        Direction const direction) -> void;
    virtual auto addFlow(Flow const* flow) -> void;
    virtual auto addAggregatedFlow(Flow const* flow) -> void;
    virtual auto resetFlow(bool resetTotal) -> void;
    virtual auto fillValues(std::map<Field, std::string>& map,
        Direction direction, int duration) const -> void;
    virtual auto mergePercentiles() -> void {};
    [[nodiscard]] virtual auto getStatsdMetrics() const -> std::vector<std::string> { return {}; };

    auto operator<(Flow const& f) -> bool
    {
        return sortByBytes(f);
    }

    [[nodiscard]] auto getFlowId() const { return flowId; };
    auto setFqdn(std::string _fqdn) { fqdn = _fqdn; };
    [[nodiscard]] auto getFqdn() const { return fqdn; };
    [[nodiscard]] auto getSrvPos() const { return srvPos; }
    [[nodiscard]] auto getPackets() const { return packets; };
    [[nodiscard]] auto getTotalBytes() const { return totalBytes; };
    [[nodiscard]] auto getTotalPackets() const { return totalPackets; };

    [[nodiscard]] auto getTransport() const { return flowId.getTransport(); };
    [[nodiscard]] auto getPort(uint8_t pos) const { return flowId.getPort(pos); }
    [[nodiscard]] auto getSrvPort() const { return flowId.getPort(srvPos); }
    [[nodiscard]] auto getSrvIp() const -> Tins::IPv4Address { return flowId.getIp(srvPos); }
    [[nodiscard]] auto getCltIp() const -> Tins::IPv4Address { return flowId.getIp(!srvPos); }
    [[nodiscard]] auto getCltIpInt() const { return flowId.getIp(!srvPos); }
    [[nodiscard]] auto getSrvIpInt() const { return flowId.getIp(srvPos); }

    [[nodiscard]] auto sortByFqdn(Flow const& b) const -> bool
    {
        return std::lexicographical_compare(
            fqdn.begin(), fqdn.end(), b.fqdn.begin(), b.fqdn.end(), caseInsensitiveComp);
    }

    [[nodiscard]] auto sortByIp(Flow const& b) const -> bool
    {
        return getSrvIp() < b.getSrvIp();
    }

    [[nodiscard]] auto sortByPort(Flow const& b) const -> bool
    {
        return getSrvPort() < b.getSrvPos();
    }

    [[nodiscard]] auto sortByBytes(Flow const& b) const -> bool
    {
        return bytes[0] + bytes[1] < b.bytes[0] + b.bytes[1];
    }

    [[nodiscard]] auto sortByTotalBytes(Flow const& b) const -> bool
    {
        return totalBytes[0] + totalBytes[1] < b.totalBytes[0] + b.totalBytes[1];
    }

    [[nodiscard]] auto sortByPackets(Flow const& b) const -> bool
    {
        return packets[0] + packets[1] < b.packets[0] + b.packets[1];
    }

    [[nodiscard]] auto sortByTotalPackets(Flow const& b) const -> bool
    {
        return totalPackets[0] + totalPackets[1] < b.totalPackets[0] + b.totalPackets[1];
    }

    typedef bool (Flow::*sortFlowFun)(Flow const&) const;

private:
    FlowId flowId;
    std::string fqdn;
    uint8_t srvPos = 1;
    timeval start = {};
    timeval end = {};

    std::array<int, 2> packets = {};
    std::array<int, 2> bytes = {};
    std::array<int, 2> totalPackets = {};
    std::array<int, 2> totalBytes = {};
};
} // namespace flowstats
