#pragma once

#include "AggregatedSslFlow.hpp"
#include "Flow.hpp"
#include "Stats.hpp"
#include <SSLLayer.h>

namespace flowstats {

class SslFlow : public Flow {
public:
    std::string domain;

    int tickets[2] = { 0, 0 };
    timespec startHandshake = { 0, 0 };

    void updateFlow(pcpp::Packet* const packet, Direction direction,
        pcpp::SSLLayer* sslLayer);
    std::vector<AggregatedSslFlow*> aggregatedFlows;

private:
    std::string getDomain(pcpp::SSLClientHelloMessage* clientHelloMessage);
    void processHandshake(pcpp::Packet* const packet, pcpp::SSLLayer* sslLayer,
        Direction direction);
};
}
