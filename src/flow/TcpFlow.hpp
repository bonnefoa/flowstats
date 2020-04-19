#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Flow.hpp"
#include "Stats.hpp"
#include <TcpLayer.h>

namespace flowstats {

class TcpFlow : public Flow {

public:
    TcpFlow();
    TcpFlow(pcpp::IPv4Layer* ipv4Layer, pcpp::TcpLayer* tcpLayer, uint32_t flowHash);

    void updateFlow(pcpp::Packet* const packet, Direction direction,
        pcpp::TcpLayer* const tcpLayer);

    uint32_t seqNum[2] = { 0, 0 };
    uint32_t finSeqnum[2] = { 0, 0 };
    bool finAcked[2] = { 0, 0 };
    uint32_t flowHash = 0;

    timespec synTime[2] = { { 0, 0 }, { 0, 0 } };
    bool synAcked[2] = { 0, 0 };
    bool hadPacket[2] = { 0, 0 };

    timespec closeTime = { 0, 0 };
    int requestSize = 0;
    int gap = 0;
    std::string fqdn = "";

    bool closed = false;
    bool opened = false;
    bool opening = false;

    Direction lastDirection;
    timespec lastPacketTime[2] = { { 0, 0 }, { 0, 0 } };
    timespec lastPayloadTime = { 0, 0 };
    void detectServer(pcpp::TcpLayer* const tcpLayer, Direction direction,
        std::map<uint16_t, int>& srvPortsCounter);
    std::vector<AggregatedTcpFlow*> aggregatedFlows;
    void closeConnection();
    void timeoutFlow();

private:
    std::string tcphdrToString(pcpp::tcphdr* const hdr);
    uint32_t nextSeqnum(pcpp::TcpLayer* const tcpLayer, int payloadSize);
    int getTcpPayloadSize(pcpp::Packet* const packet, pcpp::TcpLayer* const tcpLayer);
};
}
