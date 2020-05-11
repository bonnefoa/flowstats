#pragma once

#include "AggregatedSslFlow.hpp"
#include "Flow.hpp"
#include "PduUtils.hpp"
#include "Stats.hpp"

namespace flowstats {

class SslFlow : public Flow {
public:
    SslFlow()
        : Flow() {};
    SslFlow(Tins::IP const& ip, Tins::TCP const& tcp)
        : Flow(ip, tcp) {};
    SslFlow(FlowId const& flowId)
        : Flow(flowId) {};

    void updateFlow(Tins::Packet const& packet, Direction direction,
        Tins::IP const& ip,
        Tins::TCP const& sslLayer);
    std::vector<AggregatedSslFlow*> aggregatedFlows;

private:
    void processHandshake(Tins::Packet const& packet, Cursor* cursor);

    std::string domain = "";
    timeval startHandshake = {};
    bool connectionEstablished = false;
};
} // namespace flowstats
