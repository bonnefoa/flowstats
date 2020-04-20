#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Flow.hpp"
#include "Stats.hpp"
#include <TcpLayer.h>

namespace flowstats {

class TcpFlow : public Flow {

public:
    TcpFlow();
    TcpFlow(Tins::IPv4Layer* ipv4Layer, Tins::TcpLayer* tcpLayer, uint32_t flowHash);

    void updateFlow(Tins::Packet* const packet, Direction direction,
        Tins::TcpLayer* const tcpLayer);

    uint32_t seqNum[2] = { 0, 0 };
    uint32_t finSeqnum[2] = { 0, 0 };
    bool finAcked[2] = { 0, 0 };
    uint32_t flowHash = 0;

    timeval synTime[2] = { { 0, 0 }, { 0, 0 } };
    bool synAcked[2] = { 0, 0 };
    bool hadPacket[2] = { 0, 0 };

    timeval closeTime = { 0, 0 };
    int requestSize = 0;
    int gap = 0;
    std::string fqdn = "";

    bool closed = false;
    bool opened = false;
    bool opening = false;

    Direction lastDirection;
    timeval lastPacketTime[2] = { { 0, 0 }, { 0, 0 } };
    timeval lastPayloadTime = { 0, 0 };
    void detectServer(Tins::TcpLayer* const tcpLayer, Direction direction,
        std::map<uint16_t, int>& srvPortsCounter);
    std::vector<AggregatedTcpFlow*> aggregatedFlows;
    void closeConnection();
    void timeoutFlow();

private:
    std::string tcphdrToString(Tins::tcphdr* const hdr);
    uint32_t nextSeqnum(Tins::TcpLayer* const tcpLayer, int payloadSize);
    int getTcpPayloadSize(Tins::Packet* const packet, Tins::TcpLayer* const tcpLayer);
};
}
