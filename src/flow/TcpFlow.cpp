#include "TcpFlow.hpp"
#include "PduUtils.hpp"
#include "Utils.hpp"
#include <spdlog/spdlog.h>

namespace flowstats {

auto TcpFlow::timeoutFlow() -> void
{
    if (opening) {
        for (auto& subflow : aggregatedFlows) {
            subflow->failConnection();
        }
    }
    if (opened) {
        closeConnection();
    }
}

auto TcpFlow::closeConnection() -> void
{
    if (opened) {
        spdlog::debug("Closing connection {}", getFlowId().toString());
        for (auto& aggregatedFlow : aggregatedFlows) {
            aggregatedFlow->closeConnection();
        }
    }
    closed = true;
    opened = false;
    opening = false;

    synTime = {};
    seqNum = {};
    finSeqnum = {};
    hadPacket = {};
    finAcked = {};
    synAcked = {};
    closeTime = {};
    lastPayloadTime = {};
}

auto TcpFlow::nextSeqnum(Tins::TCP const& tcp, int tcpPayloadSize) -> uint32_t
{
    return tcp.seq() + tcpPayloadSize + tcp.has_flags(Tins::TCP::SYN) + tcp.has_flags(Tins::TCP::FIN);
}

auto TcpFlow::updateFlow(Tins::Packet const& packet, Direction direction,
    Tins::IP const& ip,
    Tins::TCP const& tcp) -> void
{
    auto const flags = tcp.flags();
    timeval tv = packetToTimeval(packet);

    int tcpPayloadSize = getTcpPayloadSize(ip, tcp);
    lastPacketTime[direction] = tv;
    uint32_t nextSeq = std::max(seqNum[direction], nextSeqnum(tcp, tcpPayloadSize));
    spdlog::debug("Update flow {}, nextSeq {}, ts {}ms, direction {}, tcp {}, payload {}",
        getFlowId().toString(), nextSeq, timevalInMs(tv), direction,
        tcpToString(tcp), tcpPayloadSize);

    auto currentDirection = static_cast<Direction>(direction == getSrvPort());
    if (flags & Tins::TCP::SYN) {
        synTime[direction] = tv;
        opening = true;
        closed = false;
        spdlog::debug("Got syn for direction {}, srvPort {}, ts {}ms",
            directionToString(currentDirection), getSrvPort(), timevalInMs(tv));
    }

    if (!opened && flags & Tins::TCP::ACK && tcp.ack_seq() == seqNum[!direction]
        && synAcked[direction] == false) {
        spdlog::debug("syn acked for direction {}", directionToString(currentDirection));
        synAcked[direction] = true;
        if (synAcked[!direction]) {
            timeval start = synTime[direction];
            timeval end = tv;
            uint32_t connectionTime = getTimevalDeltaMs(start, end);
            opened = true;
            opening = false;
            spdlog::debug("Full tcp handshake, connection is now opened, ct {}", connectionTime);
            for (auto& aggregatedFlow : aggregatedFlows) {
                aggregatedFlow->openConnection(connectionTime);
            }
        }
    }

    uint32_t ackNumber = tcp.ack_seq();
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
        if (lastDirection != direction && direction == getSrvPos() && lastPayloadTime.tv_sec > 0) {
            uint32_t delta = getTimevalDeltaMs(lastPayloadTime, tv);
            spdlog::debug("Change of direction to {}, srt {}, requestSize {}",
                directionToString(currentDirection),
                delta, requestSize);
            for (auto& aggregatedFlow : aggregatedFlows) {
                aggregatedFlow->addSrt(delta, requestSize);
            }
        }
        lastPayloadTime = tv;
        lastDirection = direction;
        if (direction == getSrvPos()) {
            requestSize = 0;
        } else {
            requestSize += tcpPayloadSize;
        }
    }

    if (!tcp.has_flags(Tins::TCP::SYN) && !tcp.has_flags(Tins::TCP::RST) && !opened && !opening && seqNum[!direction] == ackNumber) {
        spdlog::debug("Detected ongoing conversation");
        opened = true;
        for (auto& aggregatedFlow : aggregatedFlows) {
            aggregatedFlow->ongoingConnection();
        }
    }

    if (tcp.has_flags(Tins::TCP::FIN)) {
        uint32_t nextSeq = nextSeqnum(tcp, tcpPayloadSize);
        spdlog::debug("Got fin for direction {}, ts {}ms, nextSeq {}, ack {}",
            directionToString(currentDirection), timevalInMs(tv), nextSeq, tcp.ack_seq());
        finSeqnum[direction] = nextSeq;
    }

    if (tcp.has_flags(Tins::TCP::ACK)
        && tcp.ack_seq() == finSeqnum[!direction]
        && finAcked[direction] == false) {
        finAcked[direction] = true;
        if (finAcked[!direction]) {
            closeConnection();
        }
    }

    if (tcp.has_flags(Tins::TCP::RST) && closed == false) {
        closeConnection();
    }

    if (tcp.has_flags(Tins::TCP::SYN) && opening == false) {
        opening = true;
    }
}

auto TcpFlow::tcpToString(Tins::TCP const& tcp) -> std::string
{
    std::string tcpFlag;
    auto flags = tcp.flags();
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
        tcpFlag, tcp.seq(),
        tcp.ack_seq(),
        opened);
}
} // namespace flowstats
