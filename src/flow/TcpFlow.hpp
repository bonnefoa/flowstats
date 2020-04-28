#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Flow.hpp"
#include "Stats.hpp"

namespace flowstats {

class TcpFlow : public Flow {

public:
    TcpFlow();
    TcpFlow(Tins::IP const& ip, Tins::TCP const& tcp);

    auto updateFlow(Tins::Packet const& packet, Direction direction,
        Tins::IP const& ip,
        Tins::TCP const& tcp) -> void;

    std::array<uint32_t, 2> seqNum = {};
    std::array<uint32_t, 2> finSeqnum = {};
    std::array<bool, 2> finAcked = {};

    std::array<bool, 2> synAcked = {};
    std::array<bool, 2> hadPacket = {};

    int requestSize = 0;
    int gap = 0;
    std::string fqdn = "";

    bool closed = false;
    bool opened = false;
    bool opening = false;

    Direction lastDirection = FROM_CLIENT;

    std::array<timeval, 2> synTime = {};
    std::array<timeval, 2> closeTime = {};
    std::array<timeval, 2> lastPacketTime = {};
    timeval lastPayloadTime = {};

    auto detectServer(Tins::TCP const& tcp, Direction direction,
        std::map<uint16_t, int>& srvPortsCounter) -> void;
    auto closeConnection() -> void;
    auto timeoutFlow() -> void;
    auto getAggregatedFlows() const { return aggregatedFlows; }
    auto setAggregatedFlows(std::vector<AggregatedTcpFlow*> _aggregatedFlows) { aggregatedFlows = _aggregatedFlows; }

private:
    std::vector<AggregatedTcpFlow*> aggregatedFlows;
    auto tcpToString(Tins::TCP const& hdr) -> std::string;
    auto nextSeqnum(Tins::TCP const& tcp, int payloadSize) -> uint32_t;
};
}
