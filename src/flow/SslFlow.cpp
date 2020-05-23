#include "SslFlow.hpp"
#include "SslProto.hpp"
#include <spdlog/spdlog.h>
#include <tins/rawpdu.h>

namespace flowstats {

void SslFlow::processHandshake(Tins::Packet const& packet,
    Cursor* cursor)
{
    if (checkSslHandshake(cursor) == false) {
        return;
    }

    auto handshakeType = cursor->readUint8();
    if (handshakeType != SSL_CLIENT_HELLO) {
        return;
    }
    auto pduLength = cursor->readUint24();
    cursor->checkSize(pduLength - 4);

    auto sslVersion = cursor->readUint16();
    if (checkValidSslVersion(sslVersion) == false) {
        return;
    }

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
        for (auto* aggregatedSslFlow : aggregatedFlows) {
            aggregatedSslFlow->setDomain(domain);
        }
    }
}

auto SslFlow::addPacket(Tins::Packet const& packet, Direction const direction) -> void
{
    Flow::addPacket(packet, direction);
    for (auto& subflow : aggregatedFlows) {
        subflow->addPacket(packet, direction);
    }
}

void SslFlow::updateFlow(Tins::Packet const& packet, Direction direction,
    Tins::TCP const& tcp)
{
    if (connectionEstablished) {
        return;
    }

    auto rawData = tcp.find_pdu<Tins::RawPDU>();
    if (rawData == nullptr) {
        return;
    }
    auto payload = rawData->payload();
    auto cursor = Cursor(payload);
    if (direction == FROM_CLIENT) {
        processHandshake(packet, &cursor);
        return;
    }

    if (direction == FROM_SERVER) {
        if (checkSslChangeCipherSpec(&cursor) == false) {
            return;
        }
        connectionEstablished = true;
        uint32_t delta = getTimevalDeltaMs(startHandshake, packetToTimeval(packet));
        for (auto* aggregatedSslFlow : aggregatedFlows) {
            aggregatedSslFlow->addConnection(delta);
        }
    }
}
} // namespace flowstats
