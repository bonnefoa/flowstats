#pragma once

#include "AggregatedTcpFlow.hpp"
#include "Flow.hpp"
#include "Stats.hpp"

namespace flowstats {

class TcpFlow : public Flow {

public:
    TcpFlow();
    TcpFlow(Tins::IP* ip, Tins::TCP* tcp, uint32_t flowHash);

    void updateFlow(const Tins::PtrPacket& packet, Direction direction,
        const Tins::TCP* tcp);

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
    void detectServer(const Tins::TCP* tcp, Direction direction,
        std::map<uint16_t, int>& srvPortsCounter);
    std::vector<AggregatedTcpFlow*> aggregatedFlows;
    void closeConnection();
    void timeoutFlow();

private:
    std::string tcpToString(const Tins::TCP* hdr);
    uint32_t nextSeqnum(const Tins::TCP* tcp, int payloadSize);
    int getTcpPayloadSize(const Tins::PDU* pdu, const Tins::TCP* tcp);
};
}
