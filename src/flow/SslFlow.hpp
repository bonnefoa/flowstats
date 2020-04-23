#pragma once

#include "AggregatedSslFlow.hpp"
#include "Flow.hpp"
#include "Stats.hpp"

namespace flowstats {

class SslFlow : public Flow {
public:
    std::string domain;

    int tickets[2] = { 0, 0 };
    timeval startHandshake = { 0, 0 };

    void updateFlow(const Tins::Packet* packet, Direction direction,
        const Tins::TCP& sslLayer);
    std::vector<AggregatedSslFlow*> aggregatedFlows;

    //private:
    //std::string getDomain(Tins::SSLClientHelloMessage* clientHelloMessage);
    //void processHandshake(Tins::Packet* const packet, Tins::SSLLayer* sslLayer,
    //Direction direction);
};
}
