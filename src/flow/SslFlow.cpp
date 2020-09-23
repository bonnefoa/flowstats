#include "SslFlow.hpp"
#include "SslProto.hpp"
#include <tins/rawpdu.h>

namespace flowstats {

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

    auto mbTlsHeader = TlsHeader::parse(&cursor);
    if (!mbTlsHeader) {
        return;
    }
    auto tlsHeader = mbTlsHeader.value();

    if (tlsHeader.contentType == +SSLContentType::SSL_APPLICATION_DATA) {
        connectionEstablished = true;
        tlsVersion = tlsHeader.version;
        for (auto* aggregatedSslFlow : aggregatedFlows) {
            aggregatedSslFlow->setTlsVersion(tlsVersion);
        }
        return;
    } else if (tlsHeader.contentType == +SSLContentType::SSL_HANDSHAKE) {
        processHandshake(packet, &cursor);
        return;
    } else if (tlsHeader.contentType == +SSLContentType::SSL_CHANGE_CIPHER_SPEC) {
        processChangeCipherSpec(packet, &cursor);

        tlsVersion = tlsHeader.version;
        for (auto* aggregatedSslFlow : aggregatedFlows) {
            aggregatedSslFlow->setTlsVersion(tlsVersion);
        }
        return;
    }
}

void SslFlow::processHandshake(Tins::Packet const& packet,
    Cursor* cursor)
{
    auto mbTlsHandshake = TlsHandshake::parse(cursor);
    if (!mbTlsHandshake) {
        return;
    }
    auto tlsHandshake = mbTlsHandshake.value();

    if (tlsHandshake.handshakeType == +SSLHandshakeType::SSL_CLIENT_HELLO) {
        startHandshake = packetToTimeval(packet);
        SPDLOG_DEBUG("Start ssl connection at {}", timevalInMs(startHandshake));

        for (auto* aggregatedSslFlow : aggregatedFlows) {
            aggregatedSslFlow->setDomain(tlsHandshake.domain);
        }
    } else if (tlsHandshake.handshakeType == +SSLHandshakeType::SSL_SERVER_HELLO) {
        for (auto* aggregatedSslFlow : aggregatedFlows) {
            if (tlsHandshake.sslCipherSuite) {
                aggregatedSslFlow->setSslCipherSuite(tlsHandshake.sslCipherSuite);
            }
        }
    }
}

void SslFlow::processChangeCipherSpec(Tins::Packet const& packet,
    Cursor* cursor)
{
    if (checkSslChangeCipherSpec(cursor) == false) {
        return;
    }
    connectionEstablished = true;
    uint32_t delta = getTimevalDeltaMs(startHandshake, packetToTimeval(packet));
    for (auto* aggregatedSslFlow : aggregatedFlows) {
        aggregatedSslFlow->addConnection(delta);
    }
}

} // namespace flowstats
