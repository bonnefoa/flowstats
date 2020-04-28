#pragma once

#include "AggregatedSslFlow.hpp"
#include "Flow.hpp"
#include "PduUtils.hpp"
#include "Stats.hpp"

namespace flowstats {

class SslFlow : public Flow {
public:
    SslFlow();
    SslFlow(Tins::IP const& ip, Tins::TCP const& tcp);

    std::string domain = "";
    timeval startHandshake = {};
    bool connectionEstablished = false;

    void updateFlow(Tins::Packet const& packet, Direction direction,
        Tins::IP const& ip,
        Tins::TCP const& sslLayer);
    std::vector<AggregatedSslFlow*> aggregatedFlows;

private:
    void processHandshake(Tins::Packet const& packet, Cursor* cursor);
};
} // namespace flowstats
