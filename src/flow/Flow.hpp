#pragma once

#include "Field.hpp"
#include "FlowId.hpp"
#include <map>
#include <string>
#include <tins/packet.h>

namespace flowstats {

class Flow {

public:
    Flow()
        : flowId()
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
        Direction direction) const -> void;
    virtual auto mergePercentiles() -> void {};
    [[nodiscard]] virtual auto getStatsdMetrics() const -> std::vector<std::string> { return {}; };

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

    [[nodiscard]] static auto sortByFqdn(Flow const* a, Flow const* b) -> bool
    {
        return std::lexicographical_compare(
            a->fqdn.begin(), a->fqdn.end(),
            b->fqdn.begin(), b->fqdn.end(),
            caseInsensitiveComp);
    }

    [[nodiscard]] static auto sortByIp(Flow const* a, Flow const* b) -> bool
    {
        return a->getSrvIp() < b->getSrvIp();
    }

    [[nodiscard]] static auto sortByPort(Flow const* a, Flow const* b) -> bool
    {
        return a->getSrvPort() < b->getSrvPort();
    }

    [[nodiscard]] static auto sortByBytes(Flow const* a, Flow const* b) -> bool
    {
        return a->bytes[0] + a->bytes[1] < b->bytes[0] + b->bytes[1];
    }

    [[nodiscard]] static auto sortByTotalBytes(Flow const* a, Flow const* b) -> bool
    {
        return a->totalBytes[0] + a->totalBytes[1] < b->totalBytes[0] + b->totalBytes[1];
    }

    [[nodiscard]] static auto sortByPackets(Flow const* a, Flow const* b) -> bool
    {
        return a->packets[0] + a->packets[1] < b->packets[0] + b->packets[1];
    }

    [[nodiscard]] static auto sortByTotalPackets(Flow const* a, Flow const* b) -> bool
    {
        return a->totalPackets[0] + a->totalPackets[1] < b->totalPackets[0] + b->totalPackets[1];
    }

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
