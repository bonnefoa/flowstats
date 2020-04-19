#include "TcpFlow.hpp"
#include "Utils.hpp"
#include <PacketUtils.h>
#include <spdlog/spdlog.h>

namespace flowstats {

TcpFlow::TcpFlow()
    : Flow()
{
}

TcpFlow::TcpFlow(pcpp::IPv4Layer* ipv4Layer, pcpp::TcpLayer* tcpLayer, uint32_t flowHash)
    : Flow(ipv4Layer, tcpLayer)
    , flowHash(flowHash)
{
}

void TcpFlow::detectServer(pcpp::TcpLayer* const tcpLayer, Direction direction,
    std::map<uint16_t, int>& srvPortsCounter)
{
    pcpp::tcphdr* const tcphdr = tcpLayer->getTcpHeader();
    if (tcphdr->synFlag) {
        if (tcphdr->ackFlag) {
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

auto TcpFlow::nextSeqnum(pcpp::TcpLayer* const tcpLayer, int tcpPayloadSize) -> uint32_t
{
    pcpp::tcphdr* const tcphdr = tcpLayer->getTcpHeader();
    return ntohl(tcphdr->sequenceNumber) + tcpPayloadSize + tcphdr->synFlag + tcphdr->finFlag;
}

auto TcpFlow::getTcpPayloadSize(pcpp::Packet* const packet, pcpp::TcpLayer* const tcpLayer) -> int
{
    uint8_t const* start = packet->getFirstLayer()->getData();
    uint8_t const* end = tcpLayer->getLayerPayload();
    int headerLen = end - start;
    return packet->getRawPacketReadOnly()->getFrameLength() - headerLen;
}

void TcpFlow::updateFlow(pcpp::Packet* const packet, Direction direction,
    pcpp::TcpLayer* const tcpLayer)
{
    pcpp::tcphdr* const tcphdr = tcpLayer->getTcpHeader();
    timespec tv = packet->getRawPacketReadOnly()->getPacketTimeStamp();

    int tcpPayloadSize = getTcpPayloadSize(packet, tcpLayer);
    lastPacketTime[direction] = tv;
    uint32_t nextSeq = std::max(seqNum[direction], nextSeqnum(tcpLayer, tcpPayloadSize));
    spdlog::debug("Update flow {}, nextSeq {}, ts {}ms, direction {}, tcp {}, payload {}", flowId.toString(), nextSeq,
        timevalInMs(tv), direction, tcphdrToString(tcphdr), tcpPayloadSize);

    if (tcphdr->synFlag) {
        synTime[direction] = tv;
        opening = true;
        closed = false;
        spdlog::debug("Got syn for direction {}, srvPort {}, ts {}ms",
            directionToString(direction == srvPos), getSrvPort(), timevalInMs(tv));
    }
    auto currentDirection = static_cast<Direction>(direction == srvPos);

    if (!opened && tcphdr->ackFlag && ntohl(tcphdr->ackNumber) == seqNum[!direction]
        && synAcked[direction] == false) {
        spdlog::debug("syn acked for direction {}", directionToString(currentDirection));
        synAcked[direction] = true;
        if (synAcked[!direction]) {
            timespec start = synTime[direction];
            timespec end = tv;
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

    uint32_t ackNumber = ntohl(tcphdr->ackNumber);
    if (seqNum[!direction] > 0 && ackNumber > seqNum[!direction]) {
        spdlog::debug("Got a gap, ack {}, expected seqNum {}", ntohl(tcphdr->ackNumber), seqNum[!direction]);
        gap++;
        requestSize = 0;
        lastPayloadTime = { 0, 0 };
        seqNum[!direction] = std::max(seqNum[!direction], ntohl(tcphdr->ackNumber));
    }

    if (!tcphdr->rstFlag) {
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

    if (!tcphdr->synFlag && !tcphdr->rstFlag && !opened && !opening && seqNum[!direction] == ackNumber) {
        spdlog::debug("Detected ongoing conversation");
        opened = true;
        for (auto& aggregatedFlow : aggregatedFlows) {
            aggregatedFlow->activeConnections++;
        }
    }

    if (tcphdr->finFlag) {
        uint32_t nextSeq = nextSeqnum(tcpLayer, tcpPayloadSize);
        spdlog::debug("Got fin for direction {}, ts {}ms, nextSeq {}",
            directionToString(currentDirection), timevalInMs(tv), nextSeq);
        finSeqnum[direction] = nextSeq;
    }

    if (tcphdr->ackFlag && ntohl(tcphdr->ackNumber) == finSeqnum[!direction]
        && finAcked[direction] == false) {
        finAcked[direction] = true;
        if (finAcked[!direction]) {
            closeConnection();
        }
    }

    if (tcphdr->rstFlag && closed == false) {
        closeConnection();
    }
}

auto TcpFlow::tcphdrToString(pcpp::tcphdr* const hdr) -> std::string
{
    std::string tcpFlag;
    if (hdr->synFlag) {
        if (hdr->ackFlag) {
            tcpFlag = "[SYN, ACK], ";
        } else {
            tcpFlag = "[SYN], ";
        }
    } else if (hdr->finFlag) {
        if (hdr->ackFlag) {
            tcpFlag = "[FIN, ACK], ";
        } else {
            tcpFlag = "[FIN], ";
        }
    } else if (hdr->ackFlag) {
        tcpFlag = "[ACK], ";
    } else if (hdr->rstFlag) {
        tcpFlag = "[RST], ";
    }
    return fmt::format("{}seq={}, ack={}, opened={}",
        tcpFlag, ntohl(hdr->sequenceNumber),
        ntohl(hdr->ackNumber),
        opened);
}
} // namespace flowstats
