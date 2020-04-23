#include "TcpFlow.hpp"
#include "Utils.hpp"
#include <spdlog/spdlog.h>

namespace flowstats {

TcpFlow::TcpFlow()
    : Flow()
{
}

TcpFlow::TcpFlow(Tins::IP* ip, Tins::TCP* tcp, uint32_t flowHash)
    : Flow(ip, tcp)
    , flowHash(flowHash)
{
}

void TcpFlow::detectServer(const Tins::TCP* tcp, Direction direction,
    std::map<uint16_t, int>& srvPortsCounter)
{
    auto const flags = tcp->flags();
    if (flags & Tins::TCP::SYN) {
        if (flags & Tins::TCP::ACK) {
            srvPos = direction;
            srvPortsCounter[flowId.ports[srvPos]]++;
            spdlog::debug("Incrementing port {} as server port to {}", flowId.ports[srvPos], srvPortsCounter[flowId.ports[srvPos]]);
        } else {
            srvPos = !direction;
            srvPortsCounter[flowId.ports[srvPos]]++;
            spdlog::debug("Incrementing port {} as server port to {}", flowId.ports[srvPos], srvPortsCounter[flowId.ports[srvPos]]);
        }
    } else {
        int firstPortCount = 0;
        int secondPortCount = 0;
        if (srvPortsCounter.find(flowId.ports[direction]) != srvPortsCounter.end()) {
            firstPortCount = srvPortsCounter[flowId.ports[direction]];
        }
        if (srvPortsCounter.find(flowId.ports[!direction]) != srvPortsCounter.end()) {
            secondPortCount = srvPortsCounter[flowId.ports[!direction]];
        }
        if (firstPortCount > secondPortCount) {
            srvPos = direction;
        } else if (secondPortCount > firstPortCount) {
            srvPos = !direction;
        }
    }
    spdlog::debug("Server port detected: {}", flowId.ports[srvPos]);
}

void TcpFlow::timeoutFlow()
{
    if (opening) {
        for (auto& subflow : aggregatedFlows) {
            subflow->failedConnections++;
        }
    }
    if (opened) {
        closeConnection();
    }
}

void TcpFlow::closeConnection()
{
    if (opened) {
        spdlog::debug("Closing connection {}", flowId.toString());
        for (auto& aggregatedFlow : aggregatedFlows) {
            aggregatedFlow->closes++;
            aggregatedFlow->totalCloses++;
            aggregatedFlow->activeConnections--;
        }
    }
    closed = true;
    opened = false;
    opening = false;

    memset(synTime, 0, sizeof(synTime));
    memset(seqNum, 0, sizeof(seqNum));
    memset(finSeqnum, 0, sizeof(finSeqnum));
    memset(hadPacket, 0, sizeof(hadPacket));
    memset(finAcked, 0, sizeof(finAcked));
    memset(synAcked, 0, sizeof(synAcked));
    closeTime = { 0, 0 };
    lastPayloadTime = { 0, 0 };
}

auto TcpFlow::nextSeqnum(const Tins::TCP* tcp, int tcpPayloadSize) -> uint32_t
{
    return tcp->seq() + tcpPayloadSize + tcp->has_flags(Tins::TCP::SYN) + tcp->has_flags(Tins::TCP::FIN);
}

auto TcpFlow::getTcpPayloadSize(const Tins::PDU* packet, const Tins::IP* ip, const Tins::TCP* tcp) -> int
{
    return ip->advertised_size() - ip->header_size() - tcp->header_size();
}

void TcpFlow::updateFlow(const Tins::Packet& packet, Direction direction,
    const Tins::IP* ip,
    const Tins::TCP* tcp)
{
    auto const flags = tcp->flags();
    timeval tv = packetToTimeval(packet);

    auto pdu = packet.pdu();
    int tcpPayloadSize = getTcpPayloadSize(pdu, ip, tcp);
    lastPacketTime[direction] = tv;
    uint32_t nextSeq = std::max(seqNum[direction], nextSeqnum(tcp, tcpPayloadSize));
    spdlog::debug("Update flow {}, nextSeq {}, ts {}ms, direction {}, tcp {}, payload {}", flowId.toString(), nextSeq,
        timevalInMs(tv), direction, tcpToString(tcp), tcpPayloadSize);

    if (flags & Tins::TCP::SYN) {
        synTime[direction] = tv;
        opening = true;
        closed = false;
        spdlog::debug("Got syn for direction {}, srvPort {}, ts {}ms",
            directionToString(direction == srvPos), getSrvPort(), timevalInMs(tv));
    }
    auto currentDirection = static_cast<Direction>(direction == srvPos);

    if (!opened && flags & Tins::TCP::ACK && tcp->ack_seq() == seqNum[!direction]
        && synAcked[direction] == false) {
        spdlog::debug("syn acked for direction {}", directionToString(currentDirection));
        synAcked[direction] = true;
        if (synAcked[!direction]) {
            timeval start = synTime[direction];
            timeval end = tv;
            uint32_t delta = getTimevalDeltaMs(start, end);
            opened = true;
            opening = false;
            spdlog::debug("Full tcp handshake, connection is now opened, ct {}", delta);
            for (auto& aggregatedFlow : aggregatedFlows) {
                aggregatedFlow->connections.addPoint(delta);
                aggregatedFlow->numConnections++;
                aggregatedFlow->activeConnections++;
                aggregatedFlow->totalConnections++;
            }
        }
    }

    uint32_t ackNumber = tcp->ack_seq();
    if (seqNum[!direction] > 0 && ackNumber > seqNum[!direction]) {
        spdlog::debug("Got a gap, ack {}, expected seqNum {}", ackNumber, seqNum[!direction]);
        gap++;
        requestSize = 0;
        lastPayloadTime = { 0, 0 };
        seqNum[!direction] = std::max(seqNum[!direction], ackNumber);
    }

    if (!(flags & Tins::TCP::RST)) {
        seqNum[direction] = std::max(seqNum[direction], nextSeq);
    }
    if (tcpPayloadSize > 0) {
        if (lastDirection != direction && direction == srvPos && lastPayloadTime.tv_sec > 0) {
            uint32_t delta = getTimevalDeltaMs(lastPayloadTime, tv);
            spdlog::debug("Change of direction to {}, srt {}, requestSize {}",
                directionToString(currentDirection),
                delta, requestSize);
            for (auto& aggregatedFlow : aggregatedFlows) {
                aggregatedFlow->srts.addPoint(delta);
                aggregatedFlow->requestSizes.addPoint(requestSize);
                aggregatedFlow->numSrts++;
                aggregatedFlow->totalSrts++;
            }
        }
        lastPayloadTime = tv;
        lastDirection = direction;
        if (direction == srvPos) {
            requestSize = 0;
        } else {
            requestSize += tcpPayloadSize;
        }
    }

    if (!tcp->has_flags(Tins::TCP::SYN) && !tcp->has_flags(Tins::TCP::RST) && !opened && !opening && seqNum[!direction] == ackNumber) {
        spdlog::debug("Detected ongoing conversation");
        opened = true;
        for (auto& aggregatedFlow : aggregatedFlows) {
            aggregatedFlow->activeConnections++;
        }
    }

    if (tcp->has_flags(Tins::TCP::FIN)) {
        uint32_t nextSeq = nextSeqnum(tcp, tcpPayloadSize);
        spdlog::debug("Got fin for direction {}, ts {}ms, nextSeq {}, ack {}",
            directionToString(currentDirection), timevalInMs(tv), nextSeq, tcp->ack_seq());
        finSeqnum[direction] = nextSeq;
    }

    if (tcp->has_flags(Tins::TCP::ACK)
        && tcp->ack_seq() == finSeqnum[!direction]
        && finAcked[direction] == false) {
        finAcked[direction] = true;
        if (finAcked[!direction]) {
            closeConnection();
        }
    }

    if (tcp->has_flags(Tins::TCP::RST) && closed == false) {
        closeConnection();
    }
}

auto TcpFlow::tcpToString(const Tins::TCP* tcp) -> std::string
{
    std::string tcpFlag;
    auto flags = tcp->flags();
    if (flags & Tins::TCP::SYN) {
        if (flags & Tins::TCP::ACK) {
            tcpFlag = "[SYN, ACK], ";
        } else {
            tcpFlag = "[SYN], ";
        }
    } else if (flags & Tins::TCP::FIN) {
        if (flags & Tins::TCP::ACK) {
            tcpFlag = "[FIN, ACK], ";
        } else {
            tcpFlag = "[FIN], ";
        }
    } else if (flags & Tins::TCP::ACK) {
        tcpFlag = "[ACK], ";
    } else if (flags & Tins::TCP::RST) {
        tcpFlag = "[RST], ";
    }
    return fmt::format("{}seq={}, ack={}, opened={}",
        tcpFlag, tcp->seq(),
        tcp->ack_seq(),
        opened);
}
} // namespace flowstats
