#include "AggregatedTcpFlow.hpp"
#include <algorithm>

namespace flowstats {

void AggregatedTcpFlow::updateFlow(pcpp::Packet* packet, FlowId& flowId,
    pcpp::TcpLayer* tcpLayer)
{
    pcpp::tcphdr* tcphdr = tcpLayer->getTcpHeader();

    if (tcphdr->rstFlag > 0) {
        rsts[flowId.direction]++;
    }
    if (tcphdr->windowSize == 0 && tcphdr->rstFlag == 0) {
        zeroWins[flowId.direction]++;
    }
    if (tcphdr->synFlag > 0 && tcphdr->ackFlag == 0) {
        syns[flowId.direction]++;
    } else if (tcphdr->synFlag > 0 && tcphdr->ackFlag > 0) {
        synacks[flowId.direction]++;
    } else if (tcphdr->finFlag > 0) {
        fins[flowId.direction]++;
    }
    mtu[flowId.direction] = std::max(mtu[flowId.direction],
        packet->getRawPacketReadOnly()->getFrameLength());
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
        values["ip"] = getSrvIp().toString();
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
}  // namespace flowstats
