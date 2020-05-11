#include "SslFlow.hpp"
#include "SslProto.hpp"
#include <spdlog/spdlog.h>
#include <tins/rawpdu.h>

namespace flowstats {

void SslFlow::processHandshake(Tins::Packet const& packet,
    Cursor* cursor)
{
    checkSslHandshake(cursor);

    auto handshakeType = cursor->readUint8();
    if (handshakeType != SSL_CLIENT_HELLO) {
        return;
    }
    auto pduLength = cursor->readUint24();
    cursor->checkSize(pduLength - 4);

    auto sslVersion = cursor->readUint16();
    checkValidSslVersion(sslVersion);

    startHandshake = packetToTimeval(packet);
    spdlog::debug("Start ssl connection at {}", timevalInMs(startHandshake));

    // Random
    cursor->skip(32);
    auto sessionIdLength = cursor->readUint8();
    cursor->skip(sessionIdLength);
    auto cipherSuiteLength = cursor->readUint16();
    cursor->skip(cipherSuiteLength);
    auto compressionMethodLength = cursor->readUint8();
    cursor->skip(compressionMethodLength);

    auto extractedDomain = getSslDomainFromExtension(cursor);
    if (extractedDomain != "") {
        domain = extractedDomain;
        for (auto aggregatedSslFlow : aggregatedFlows) {
            aggregatedSslFlow->domain = domain;
        }
    }
}

void SslFlow::updateFlow(Tins::Packet const& packet, Direction direction,
    Tins::IP const& ip,
    Tins::TCP const& tcp)
{
    if (connectionEstablished) {
        return;
    }

    auto rawData = tcp.rfind_pdu<Tins::RawPDU>();
    auto payload = rawData.payload();
    auto cursor = Cursor(payload);
    if (direction == FROM_CLIENT) {
        processHandshake(packet, &cursor);
        return;
    }

    if (direction == FROM_SERVER) {
        checkSslChangeCipherSpec(&cursor);
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
