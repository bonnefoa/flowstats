#include "SslFlow.hpp"
#include <spdlog/spdlog.h>

namespace flowstats {

auto
SslFlow::getDomain(pcpp::SSLClientHelloMessage* clientHelloMessage) -> std::string
{
    auto* sniExt = clientHelloMessage
                                                         ->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
    if (sniExt != nullptr) {
        return sniExt->getHostName();
    }
    return "";
}

void SslFlow::processHandshake(pcpp::Packet* const packet, pcpp::SSLLayer* sslLayer,
    Direction direction)
{
    auto* handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer*>(sslLayer);
    if (handshakeLayer == nullptr) {
        return;
    }
    auto* clientHelloMessage = handshakeLayer
                                                          ->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
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
                                                              ->getExtensionOfType<pcpp::SSLNewSessionTicketMessage>();
        if (ticketMessage != nullptr) {
            tickets[direction]++;
            for (auto aggregatedSslFlow : aggregatedFlows) {
                aggregatedSslFlow->tickets[direction]++;
            }
        }
    }

    auto* sslFinishedMessage = handshakeLayer
                                                      ->getHandshakeMessageOfType<pcpp::SSLUnknownMessage>();
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

void SslFlow::updateFlow(pcpp::Packet* const packet, Direction direction,
    pcpp::SSLLayer* sslLayer)
{
    while (sslLayer != nullptr) {
        pcpp::SSLRecordType recType = sslLayer->getRecordType();
        if (recType == pcpp::SSL_HANDSHAKE) {
            processHandshake(packet, sslLayer, direction);
        }

        sslLayer = packet->getNextLayerOfType<pcpp::SSLLayer>(sslLayer);
    }
}
}  // namespace flowstats
