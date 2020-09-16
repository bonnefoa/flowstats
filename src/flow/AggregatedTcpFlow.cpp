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
        totalRsts[direction]++;
    }

    if (tcp.window() == 0 && !tcp.has_flags(Tins::TCP::RST)) {
        zeroWins[direction]++;
        totalZeroWins[direction]++;
    }

    if (tcp.has_flags(Tins::TCP::SYN | Tins::TCP::ACK)) {
        synAcks[direction]++;
        totalSynAcks[direction]++;
    } else if (tcp.has_flags(Tins::TCP::SYN)) {
        syns[direction]++;
        totalSyns[direction]++;
    } else if (tcp.has_flags(Tins::TCP::FIN)) {
        fins[direction]++;
        totalFins[direction]++;
    }
    mtu[direction] = std::max(mtu[direction],
        packet.pdu()->advertised_size());
}

auto AggregatedTcpFlow::getFieldStr(Field field, Direction direction, int duration) const -> std::string
{
    if (direction == MERGED) {
        switch (field) {
            case Field::SYN_RATE: return std::to_string(syns[FROM_CLIENT] + syns[FROM_SERVER]);
            case Field::SYNACK_RATE: return std::to_string(synAcks[FROM_CLIENT] + synAcks[FROM_SERVER]);
            case Field::FIN_RATE: return std::to_string(fins[FROM_CLIENT] + fins[FROM_SERVER]);
            case Field::ZWIN_RATE: return std::to_string(zeroWins[FROM_CLIENT] + zeroWins[FROM_SERVER]);
            case Field::RST_RATE: return std::to_string(rsts[FROM_CLIENT] + rsts[FROM_SERVER]);

            case Field::SYN: return std::to_string(totalSyns[FROM_CLIENT] + totalSyns[FROM_SERVER]);
            case Field::SYNACK: return std::to_string(totalSynAcks[FROM_CLIENT] + totalSynAcks[FROM_SERVER]);
            case Field::FIN: return std::to_string(totalFins[FROM_CLIENT] + totalFins[FROM_SERVER]);
            case Field::ZWIN: return std::to_string(totalZeroWins[FROM_CLIENT] + totalZeroWins[FROM_SERVER]);
            case Field::RST: return std::to_string(totalRsts[FROM_CLIENT] + totalRsts[FROM_SERVER]);

            case Field::MTU: return std::to_string(std::max(mtu[FROM_CLIENT], mtu[FROM_SERVER]));
            default: break;
        }
    } else {
        switch (field) {
            case Field::SYN_RATE: return std::to_string(syns[direction]);
            case Field::SYNACK_RATE: return std::to_string(synAcks[direction]);
            case Field::FIN_RATE: return std::to_string(fins[direction]);
            case Field::ZWIN_RATE: return std::to_string(zeroWins[direction]);
            case Field::RST_RATE: return std::to_string(rsts[direction]);

            case Field::SYN: return std::to_string(totalSyns[direction]);
            case Field::SYNACK: return std::to_string(totalSynAcks[direction]);
            case Field::FIN: return std::to_string(totalFins[direction]);
            case Field::ZWIN: return std::to_string(totalZeroWins[direction]);
            case Field::RST: return std::to_string(totalRsts[direction]);

            case Field::MTU: return std::to_string(mtu[direction]);
            default: break;
        }
    }

    if (direction == FROM_CLIENT || direction == MERGED) {
        switch (field) {
            case Field::ACTIVE_CONNECTIONS: return std::to_string(activeConnections);
            case Field::FAILED_CONNECTIONS: return std::to_string(failedConnections);
            case Field::CLOSE: return std::to_string(totalCloses);
            case Field::CONN: return prettyFormatNumber(totalConnections);
            case Field::CT_P95: return connections.getPercentileStr(0.95);
            case Field::CT_P99: return connections.getPercentileStr(0.99);

            case Field::SRT: return prettyFormatNumber(totalSrts);
            case Field::SRT_P95: return srts.getPercentileStr(0.95);
            case Field::SRT_P99: return srts.getPercentileStr(0.99);

            case Field::DS_P95: return prettyFormatBytes(requestSizes.getPercentile(0.95));
            case Field::DS_P99: return prettyFormatBytes(requestSizes.getPercentile(0.99));
            case Field::DS_MAX: return prettyFormatBytes(requestSizes.getPercentile(1));

            case Field::FQDN: return getFqdn();
            case Field::IP: return getSrvIp();
            case Field::PORT: return std::to_string(getSrvPort());

            case Field::CONN_RATE: return std::to_string(numConnections);
            case Field::CLOSE_RATE: return std::to_string(closes);
            case Field::SRT_RATE: return prettyFormatNumber(numSrts);
            default: break;
        }
    }
    return Flow::getFieldStr(field, direction, duration);
}

auto AggregatedTcpFlow::addAggregatedFlow(Flow const* flow) -> void
{
    Flow::addFlow(flow);

    auto const* tcpFlow = dynamic_cast<const AggregatedTcpFlow*>(flow);
    for (int i = 0; i <= FROM_SERVER; ++i) {
        syns[i] += tcpFlow->syns[i];
        fins[i] += tcpFlow->fins[i];
        rsts[i] += tcpFlow->rsts[i];
        zeroWins[i] += tcpFlow->zeroWins[i];

        totalSyns[i] += tcpFlow->totalSyns[i];
        totalFins[i] += tcpFlow->totalFins[i];
        totalRsts[i] += tcpFlow->totalRsts[i];
        totalZeroWins[i] += tcpFlow->totalZeroWins[i];

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

    syns = {};
    synAcks = {};
    fins = {};
    rsts = {};
    zeroWins = {};

    if (resetTotal) {
        totalSyns = {};
        totalSynAcks = {};
        totalFins = {};
        totalRsts = {};
        totalZeroWins = {};
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
