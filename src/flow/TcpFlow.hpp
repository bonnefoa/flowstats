#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Flow.hpp"
#include "Stats.hpp"

namespace flowstats {

class TcpFlow : public Flow {

public:
    TcpFlow()
        : Flow() {};
    TcpFlow(FlowId flowId,
        uint8_t srvPos,
        std::vector<AggregatedTcpFlow*> _aggregatedFlows)
        : Flow(std::move(flowId), "", srvPos)
        , aggregatedFlows(std::move(_aggregatedFlows))
    {
    }

    auto updateFlow(Tins::Packet const& packet, Direction direction,
        Tins::IP const* ip,
        Tins::IPv6 const* ipv6,
        Tins::TCP const& tcp) -> void;
    auto closeConnection() -> void;
    auto timeoutFlow() -> void;

    [[nodiscard]] auto getTcpAggregatedFlows() const { return aggregatedFlows; }
    [[nodiscard]] auto getLastPacketTime() const { return lastPacketTime; }
    [[nodiscard]] auto getGap() const { return gap; }

private:
    std::vector<AggregatedTcpFlow*> aggregatedFlows;
    auto tcpToString(Tins::TCP const& hdr) -> std::string;
    auto nextSeqnum(Tins::TCP const& tcp, int payloadSize) -> uint32_t;

    std::array<uint32_t, 2> seqNum = {};
    std::array<uint32_t, 2> finSeqnum = {};
    std::array<bool, 2> finAcked = {};

    std::array<bool, 2> synAcked = {};
    std::array<bool, 2> hadPacket = {};

    int requestSize = 0;
    int gap = 0;

    bool closed = false;
    bool opened = false;
    bool opening = false;

    Direction lastDirection = FROM_CLIENT;

    std::array<timeval, 2> synTime = {};
    std::array<timeval, 2> closeTime = {};
    std::array<timeval, 2> lastPacketTime = {};
    timeval lastPayloadTime = {};
};
} // namespace flowstats
