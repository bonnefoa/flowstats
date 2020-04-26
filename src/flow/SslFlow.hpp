#pragma once

#include "AggregatedSslFlow.hpp"
#include "Flow.hpp"
#include "PduUtils.hpp"
#include "Stats.hpp"

namespace flowstats {

class SslFlow : public Flow {
public:
    SslFlow();
    SslFlow(const Tins::IP& ip, const Tins::TCP& tcp);

    std::string domain;

    timeval startHandshake = {};
    bool connectionEstablished = false;

    void updateFlow(const Tins::Packet& packet, Direction direction,
        const Tins::IP& ip,
        const Tins::TCP& sslLayer);
    std::vector<AggregatedSslFlow*> aggregatedFlows;

private:
    //std::string getDomain(Tins::SSLClientHelloMessage* clientHelloMessage);
    void processHandshake(const Tins::Packet& packet, Cursor* cursor);
};
} // namespace flowstats
