#include "SslFlow.hpp"
#include "SslProto.hpp"
#include <rawpdu.h>
#include <spdlog/spdlog.h>

namespace flowstats {

SslFlow::SslFlow()
    : Flow()
{
}

SslFlow::SslFlow(const Tins::IP& ip, const Tins::TCP& tcp)
    : Flow(ip, tcp)
{
}

void SslFlow::processHandshake(const Tins::Packet& packet,
    Cursor* cursor)
{
    auto handshakeType = cursor->readUint8();
    if (handshakeType == SSL_CLIENT_HELLO) {
        auto length = cursor->readUint24();
        cursor->checkSize(length - 4);
        startHandshake = packetToTimeval(packet);
        spdlog::debug("Starts ssl connection at {}", timevalInMs(startHandshake));
        return;
    }
}

void SslFlow::updateFlow(const Tins::Packet& packet, Direction direction,
    const Tins::IP& ip,
    const Tins::TCP& tcp)
{
    if (connectionEstablished) {
        return;
    }

    auto rawData = tcp.rfind_pdu<Tins::RawPDU>();
    auto payload = rawData.payload();
    auto cursor = Cursor(payload);
    if (direction == FROM_CLIENT && isSslHandshake(&cursor)) {
        processHandshake(packet, &cursor);
        return;
    }

    if (direction == FROM_SERVER && isSslChangeCipherSpec(&cursor)) {
        connectionEstablished = true;
        uint32_t delta = getTimevalDeltaMs(startHandshake, packetToTimeval(packet));
        for (auto aggregatedSslFlow : aggregatedFlows) {
            aggregatedSslFlow->connections.addPoint(delta);
            aggregatedSslFlow->numConnections++;
            aggregatedSslFlow->totalConnections++;
        }
    }
}
} // namespace flowstats
