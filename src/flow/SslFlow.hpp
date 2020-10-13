#pragma once

#include "AggregatedSslFlow.hpp"
#include "Flow.hpp"
#include "PduUtils.hpp"
#include "SslProto.hpp"
#include "Stats.hpp"

namespace flowstats {

class SslFlow : public Flow {
public:
    SslFlow()
        : Flow() {};
    SslFlow(FlowId const& flowId,
        std::string const& fqdn,
        std::vector<AggregatedSslFlow*> _aggregatedFlows)
        : Flow(flowId, fqdn)
        , aggregatedFlows(std::move(_aggregatedFlows)) {};

    void updateFlow(Tins::Packet const& packet, Direction direction,
        Tins::TCP const& sslLayer);

    auto addPacket(Tins::Packet const& packet, Direction const direction) -> void override;

private:
    void processHandshake(Tins::Packet const& packet, Cursor* cursor);
    void processChangeCipherSpec(Tins::Packet const& packet,
        Cursor* cursor);

    std::vector<AggregatedSslFlow*> aggregatedFlows;
    TLSVersion tlsVersion = TLSVersion::UNKNOWN;
    timeval startHandshake = {};
    bool connectionEstablished = false;
};
} // namespace flowstats
