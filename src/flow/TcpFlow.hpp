#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Flow.hpp"
#include "Stats.hpp"

namespace flowstats {

class TcpFlow : public Flow {

public:
    TcpFlow();
    TcpFlow(const Tins::IP& ip, const Tins::TCP& tcp, uint32_t flowHash);

    auto updateFlow(const Tins::Packet& packet, Direction direction,
        const Tins::IP& ip,
        const Tins::TCP& tcp) -> void;

    std::array<uint32_t, 2> seqNum = {};
    std::array<uint32_t, 2> finSeqnum = {};
    std::array<bool, 2> finAcked = {};
    uint32_t flowHash = 0;

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

    auto detectServer(const Tins::TCP& tcp, Direction direction,
        std::map<uint16_t, int>& srvPortsCounter) -> void;
    auto closeConnection() -> void;
    auto timeoutFlow() -> void;
    auto getAggregatedFlows() const { return aggregatedFlows; }
    auto setAggregatedFlows(std::vector<AggregatedTcpFlow*> _aggregatedFlows) { aggregatedFlows = _aggregatedFlows; }

private:
    std::vector<AggregatedTcpFlow*> aggregatedFlows;
    auto tcpToString(const Tins::TCP& hdr) -> std::string;
    auto nextSeqnum(const Tins::TCP& tcp, int payloadSize) -> uint32_t;
    auto getTcpPayloadSize(const Tins::PDU* pdu, const Tins::IP& ip, const Tins::TCP& tcp) -> int;
};
}
