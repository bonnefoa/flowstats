#include "SslFlow.hpp"
#include <spdlog/spdlog.h>

namespace flowstats {

auto SslFlow::getDomain(Tins::SSLClientHelloMessage* clientHelloMessage) -> std::string
{
    auto* sniExt = clientHelloMessage
                       ->getExtensionOfType<Tins::SSLServerNameIndicationExtension>();
    if (sniExt != nullptr) {
        return sniExt->getHostName();
    }
    return "";
}

void SslFlow::processHandshake(Tins::Packet* const packet, Tins::SSLLayer* sslLayer,
    Direction direction)
{
    auto* handshakeLayer = dynamic_cast<Tins::SSLHandshakeLayer*>(sslLayer);
    if (handshakeLayer == nullptr) {
        return;
    }
    auto* clientHelloMessage = handshakeLayer
                                   ->getHandshakeMessageOfType<Tins::SSLClientHelloMessage>();
    if (clientHelloMessage != nullptr) {
        startHandshake = packet->getRawPacketReadOnly()->getPacketTimeStamp();
        std::string hostName = getDomain(clientHelloMessage);
        if (!hostName.empty()) {
            domain = hostName;
            for (auto aggregatedSslFlow : aggregatedFlows) {
                aggregatedSslFlow->domain = domain;
            }
        }
        auto* ticketMessage = clientHelloMessage
                                  ->getExtensionOfType<Tins::SSLNewSessionTicketMessage>();
        if (ticketMessage != nullptr) {
            tickets[direction]++;
            for (auto aggregatedSslFlow : aggregatedFlows) {
                aggregatedSslFlow->tickets[direction]++;
            }
        }
    }

    auto* sslFinishedMessage = handshakeLayer
                                   ->getHandshakeMessageOfType<Tins::SSLUnknownMessage>();
    if (direction == FROM_SERVER && sslFinishedMessage) {
        uint32_t delta = getTimevalDeltaMs(startHandshake,
            packet->getRawPacketReadOnly()->getPacketTimeStamp());
        spdlog::debug("End of tls handshake, handshake time {}", delta);
        for (auto aggregatedSslFlow : aggregatedFlows) {
            aggregatedSslFlow->connections.addPoint(delta);
            aggregatedSslFlow->numConnections++;
            aggregatedSslFlow->totalConnections++;
        }
    }
}

void SslFlow::updateFlow(Tins::Packet* const packet, Direction direction,
    Tins::SSLLayer* sslLayer)
{
    while (sslLayer != nullptr) {
        Tins::SSLRecordType recType = sslLayer->getRecordType();
        if (recType == Tins::SSL_HANDSHAKE) {
            processHandshake(packet, sslLayer, direction);
        }

        sslLayer = packet->getNextLayerOfType<Tins::SSLLayer>(sslLayer);
    }
}
} // namespace flowstats
