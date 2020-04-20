#include "AggregatedTcpFlow.hpp"
#include <algorithm>

namespace flowstats {

void AggregatedTcpFlow::updateFlow(Tins::PDU* pdu, FlowId& flowId,
    Tins::TCP* tcp)
{
    auto flags = tcp->flags();

    if (flags & Tins::TCP::RST) {
        rsts[flowId.direction]++;
    }
    if (tcp->window() == 0 && (flags == Tins::TCP::RST)) {
        zeroWins[flowId.direction]++;
    }
    if (flags == Tins::TCP::SYN) {
        syns[flowId.direction]++;
    } else if (flags == (Tins::TCP::SYN | Tins::TCP::ACK)) {
        synacks[flowId.direction]++;
    } else if (flags == Tins::TCP::FIN) {
        fins[flowId.direction]++;
    }
    mtu[flowId.direction] = std::max(mtu[flowId.direction],
        pdu->advertised_size());
}

void AggregatedTcpFlow::fillValues(std::map<std::string, std::string>& values,
    Direction direction, int duration)
{
    Flow::fillValues(values, direction, duration);
    values["syn"] = std::to_string(syns[direction]);
    values["synack"] = std::to_string(synacks[direction]);
    values["fin"] = std::to_string(fins[direction]);
    values["zwin"] = std::to_string(zeroWins[direction]);
    values["rst"] = std::to_string(rsts[direction]);
    values["mtu"] = std::to_string(mtu[direction]);

    if (direction == FROM_CLIENT) {
        values["active_connections"] = std::to_string(activeConnections);
        values["failed_connections"] = std::to_string(failedConnections);
        values["close"] = std::to_string(totalCloses);
        values["conn"] = prettyFormatNumber(totalConnections);
        values["ctp95"] = connections.getPercentileStr(0.95);
        values["ctp99"] = connections.getPercentileStr(0.99);

        values["srt"] = prettyFormatNumber(totalSrts);
        values["srt95"] = srts.getPercentileStr(0.95);
        values["srt99"] = srts.getPercentileStr(0.99);
        values["srtMax"] = srts.getPercentileStr(1);

        values["ds95"] = prettyFormatBytes(requestSizes.getPercentile(0.95));
        values["ds99"] = prettyFormatBytes(requestSizes.getPercentile(0.99));
        values["dsMax"] = prettyFormatBytes(requestSizes.getPercentile(1));

        values["fqdn"] = fqdn;
        values["ip"] = getSrvIp().to_string();
        values["port"] = std::to_string(getSrvPort());
        if (duration) {
            values["conn_s"] = std::to_string(connections.getCount() / duration);
            values["close_s"] = std::to_string(totalCloses / duration);
            values["srt_s"] = prettyFormatNumber(numSrts);
        } else {
            values["conn_s"] = std::to_string(numConnections);
            values["close_s"] = std::to_string(closes);
            values["srt_s"] = prettyFormatNumber(numSrts);
        }
    }
}

void AggregatedTcpFlow::resetFlow(bool resetTotal)
{
    Flow::resetFlow(resetTotal);
    srts.reset();
    requestSizes.reset();
    connections.reset();
    numConnections = 0;
    numSrts = 0;
    closes = 0;

    if (resetTotal) {
        totalCloses = 0;
        totalConnections = 0;
        totalSrts = 0;
    }
}
} // namespace flowstats
