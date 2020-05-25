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
    if (pduLength.has_value() == false) {
        return;
    }
    if (cursor->checkSize(pduLength.value() - 4) == false) {
        return;
    };

    auto sslVersion = cursor->readUint16();
    if (checkValidSslVersion(sslVersion) == false) {
        return;
    }

    startHandshake = packetToTimeval(packet);
    spdlog::debug("Start ssl connection at {}", timevalInMs(startHandshake));

    // Random
    if (cursor->skip(32) == false) {
        return;
    };
    auto sessionIdLength = cursor->readUint8();
    if (cursor->skip(sessionIdLength) == false) {
        return;
    };
    auto cipherSuiteLength = cursor->readUint16();
    if (cursor->skip(cipherSuiteLength) == false) {
        return;
    };
    auto compressionMethodLength = cursor->readUint8();
    if (cursor->skip(compressionMethodLength) == false) {
        return;
    }

    auto extractedDomain = getSslDomainFromExtension(cursor);
    if (extractedDomain.value_or("") != "") {
        domain = extractedDomain.value();
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

    auto const* rawData = tcp.find_pdu<Tins::RawPDU>();
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
