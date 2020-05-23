#include "AggregatedTcpFlow.hpp"
#include <algorithm>

namespace flowstats {

AggregatedTcpFlow::~AggregatedTcpFlow()
{
    connections.resetAndShrink();
    srts.resetAndShrink();
    requestSizes.resetAndShrink();
}

auto AggregatedTcpFlow::updateFlow(Tins::Packet const& packet,
    FlowId const& flowId,
    Tins::TCP const& tcp) -> void
{
    auto direction = flowId.getDirection();
    if (tcp.has_flags(Tins::TCP::RST)) {
        rsts[direction]++;
    }

    if (tcp.window() == 0 && !tcp.has_flags(Tins::TCP::RST)) {
        zeroWins[direction]++;
    }

    if (tcp.has_flags(Tins::TCP::SYN | Tins::TCP::ACK)) {
        synacks[direction]++;
    } else if (tcp.has_flags(Tins::TCP::SYN)) {
        syns[direction]++;
    } else if (tcp.has_flags(Tins::TCP::FIN)) {
        fins[direction]++;
    }
    mtu[direction] = std::max(mtu[direction],
        packet.pdu()->advertised_size());
}

auto AggregatedTcpFlow::fillValues(std::map<Field, std::string>& values,
    Direction direction) const -> void
{
    Flow::fillValues(values, direction);
    values[Field::SYN] = std::to_string(syns[direction]);
    values[Field::SYNACK] = std::to_string(synacks[direction]);
    values[Field::FIN] = std::to_string(fins[direction]);
    values[Field::ZWIN] = std::to_string(zeroWins[direction]);
    values[Field::RST] = std::to_string(rsts[direction]);
    values[Field::MTU] = std::to_string(mtu[direction]);

    if (direction == FROM_CLIENT) {
        values[Field::ACTIVE_CONNECTIONS] = std::to_string(activeConnections);
        values[Field::FAILED_CONNECTIONS] = std::to_string(failedConnections);
        values[Field::CLOSE] = std::to_string(totalCloses);
        values[Field::CONN] = prettyFormatNumber(totalConnections);
        values[Field::CT_P95] = connections.getPercentileStr(0.95);
        values[Field::CT_P99] = connections.getPercentileStr(0.99);

        values[Field::SRT] = prettyFormatNumber(totalSrts);
        values[Field::SRT_P95] = srts.getPercentileStr(0.95);
        values[Field::SRT_P99] = srts.getPercentileStr(0.99);

        values[Field::DS_P95] = prettyFormatBytes(requestSizes.getPercentile(0.95));
        values[Field::DS_P99] = prettyFormatBytes(requestSizes.getPercentile(0.99));
        values[Field::DS_MAX] = prettyFormatBytes(requestSizes.getPercentile(1));

        values[Field::FQDN] = getFqdn();
        values[Field::IP] = getSrvIp();
        values[Field::PORT] = std::to_string(getSrvPort());

        values[Field::CONN_RATE] = std::to_string(numConnections);
        values[Field::CLOSE_RATE] = std::to_string(closes);
        values[Field::SRT_RATE] = prettyFormatNumber(numSrts);
    }
}

auto AggregatedTcpFlow::addAggregatedFlow(Flow const* flow) -> void
{
    auto const* tcpFlow = dynamic_cast<const AggregatedTcpFlow*>(flow);
    for (int i = 0; i <= FROM_SERVER; ++i) {
        syns[i] += tcpFlow->syns[i];
        fins[i] += tcpFlow->fins[i];
        rsts[i] += tcpFlow->rsts[i];
        zeroWins[i] += tcpFlow->zeroWins[i];
        mtu[i] = std::max(mtu[i], tcpFlow->mtu[i]);
    }

    closes += tcpFlow->closes;
    totalCloses += tcpFlow->totalCloses;

    activeConnections += tcpFlow->activeConnections;
    failedConnections += tcpFlow->failedConnections;

    numConnections += tcpFlow->numConnections;
    totalConnections += tcpFlow->totalConnections;

    numSrts += tcpFlow->numSrts;
    totalSrts += tcpFlow->totalSrts;

    connections.addPoints(tcpFlow->connections);
    srts.addPoints(tcpFlow->srts);
    requestSizes.addPoints(tcpFlow->requestSizes);
}

auto AggregatedTcpFlow::resetFlow(bool resetTotal) -> void
{
    Flow::resetFlow(resetTotal);

    closes = 0;
    numConnections = 0;
    numSrts = 0;

    if (resetTotal) {
        syns = {};
        fins = {};
        rsts = {};
        zeroWins = {};
        mtu = {};

        activeConnections = 0;
        failedConnections = 0;

        totalCloses = 0;
        totalConnections = 0;
        totalSrts = 0;
    }

    connections.reset();
    srts.reset();
    requestSizes.reset();
}

auto AggregatedTcpFlow::failConnection() -> void
{
    failedConnections++;
};

auto AggregatedTcpFlow::mergePercentiles() -> void
{
    srts.merge();
    connections.merge();
    requestSizes.merge();
}

auto AggregatedTcpFlow::ongoingConnection() -> void
{
    activeConnections++;
};

auto AggregatedTcpFlow::openConnection(int connectionTime) -> void
{
    connections.addPoint(connectionTime);
    numConnections++;
    activeConnections++;
    totalConnections++;
};

auto AggregatedTcpFlow::addSrt(int srt, int dataSize) -> void
{
    srts.addPoint(srt);
    requestSizes.addPoint(dataSize);
    numSrts++;
    totalSrts++;
};

auto AggregatedTcpFlow::closeConnection() -> void
{
    closes++;
    totalCloses++;
    activeConnections--;
};

auto AggregatedTcpFlow::getStatsdMetrics() const -> std::vector<std::string>
{
    std::vector<std::string> lst;
    DogFood::Tags tags = DogFood::Tags({ { "fqdn", getFqdn() },
        { "ip", getSrvIp() },
        { "port", std::to_string(getSrvPort()) } });
    for (auto& i : srts.getPoints()) {
        lst.push_back(DogFood::Metric("flowstats.tcp.srt", i,
            DogFood::Histogram, 1, tags));
    }
    for (auto& i : connections.getPoints()) {
        lst.push_back(DogFood::Metric("flowstats.tcp.ct", i,
            DogFood::Histogram, 1, tags));
    }
    if (activeConnections) {
        lst.push_back(DogFood::Metric("flowstats.tcp.activeConnections", activeConnections, DogFood::Counter, 1, tags));
    }
    if (failedConnections) {
        lst.push_back(DogFood::Metric("flowstats.tcp.failedConnections", failedConnections,
            DogFood::Counter, 1, tags));
    }
    return lst;
}

} // namespace flowstats
