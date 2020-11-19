#include "TcpAggregatedFlow.hpp"
#include "Utils.hpp"
#include <algorithm>

namespace flowstats {

TcpAggregatedFlow::~TcpAggregatedFlow()
{
    connectionTimes.resetAndShrink();
    totalConnectionTimes.resetAndShrink();
    srts.resetAndShrink();
    totalSrts.resetAndShrink();
    requestSizes.resetAndShrink();
    totalRequestSizes.resetAndShrink();
}

auto TcpAggregatedFlow::updateFlow(Tins::Packet const& packet,
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

auto TcpAggregatedFlow::getSubfieldSize(Field field) const -> int
{
    switch (field) {
        case Field::TOP_CLIENT_IPS_IP:
        case Field::TOP_CLIENT_IPS_BYTES:
        case Field::TOP_CLIENT_IPS_PKTS:
            return std::min(5, static_cast<int>(sourceIpToStats.size()));
        default:
            return 0;
    }
    return 0;
}

auto TcpAggregatedFlow::prepareSubfields(std::vector<Field> const& subfields) -> void
{
    for (auto field : subfields) {
        if (field == +Field::TOP_CLIENT_IPS_IP) {
            computeTopClientIps(TrafficStatsTcp::PKTS);
        }
    }
}

auto TcpAggregatedFlow::computeTopClientIps(TrafficStatsTcp::TrafficType type) -> void
{
    int size = std::min(5, static_cast<int>(sourceIpToStats.size()));
    topClientIps = std::vector<std::pair<IPAddress, TrafficStatsTcp>>(size);

    bool (*sortFun)(std::pair<IPAddress, TrafficStatsTcp> const& l,
        std::pair<IPAddress, TrafficStatsTcp> const& r)
        = [](std::pair<IPAddress, TrafficStatsTcp> const& l,
              std::pair<IPAddress, TrafficStatsTcp> const& r) {
              return l.second.bytes > r.second.bytes;
          };

    if (type == TrafficStatsTcp::PKTS) {
        sortFun = [](std::pair<IPAddress, TrafficStatsTcp> const& l,
                      std::pair<IPAddress, TrafficStatsTcp> const& r) {
            return l.second.pkts > r.second.pkts;
        };
    }
    std::partial_sort_copy(sourceIpToStats.begin(), sourceIpToStats.end(),
        topClientIps.begin(), topClientIps.end(), sortFun);
}

auto TcpAggregatedFlow::getTopClientIpsKey(int index) const -> std::string
{
    return topClientIps[index].first.getAddrStr();
}

auto TcpAggregatedFlow::getTopClientIpsValue(TrafficStatsTcp::TrafficType type, int index) const -> std::string
{
    std::string val;
    auto const& stat = topClientIps[index].second;
    if (type == TrafficStatsTcp::PKTS) {
        val = prettyFormatNumber(stat.pkts);
    } else {
        val = prettyFormatBytes(stat.bytes);
    }
    return val;
}

auto TcpAggregatedFlow::getFieldStr(Field field, Direction direction, int duration, int index) const -> std::string
{

    if (index > 0) {
        switch (field) {
            case Field::TOP_CLIENT_IPS_IP: return getTopClientIpsKey(index);
            case Field::TOP_CLIENT_IPS_BYTES: return getTopClientIpsValue(TrafficStatsTcp::BYTES, index);
            case Field::TOP_CLIENT_IPS_PKTS: return getTopClientIpsValue(TrafficStatsTcp::PKTS, index);
            default: return "";
        }
    }

    auto fqdn = getFqdn();
    if (fqdn == "Total") {
        if (direction == FROM_CLIENT || direction == MERGED) {
            switch (field) {
                case Field::PORT: return "-";
                default: break;
            }
        }
    }

    if (direction == MERGED) {
        switch (field) {
            case Field::SYN_RATE: return std::to_string(syns[FROM_CLIENT] + syns[FROM_SERVER]);
            case Field::SYNACK_RATE: return std::to_string(synAcks[FROM_CLIENT] + synAcks[FROM_SERVER]);
            case Field::FIN_RATE: return std::to_string(fins[FROM_CLIENT] + fins[FROM_SERVER]);
            case Field::ZWIN_RATE: return std::to_string(zeroWins[FROM_CLIENT] + zeroWins[FROM_SERVER]);
            case Field::RST_RATE: return std::to_string(rsts[FROM_CLIENT] + rsts[FROM_SERVER]);

            case Field::SYN_AVG: return prettyFormatNumberAverage(totalSyns[FROM_CLIENT] + totalSyns[FROM_SERVER], duration);
            case Field::SYNACK_AVG: return prettyFormatNumberAverage(totalSynAcks[FROM_CLIENT] + totalSynAcks[FROM_SERVER], duration);
            case Field::FIN_AVG: return prettyFormatNumberAverage(totalFins[FROM_CLIENT] + totalFins[FROM_SERVER], duration);
            case Field::ZWIN_AVG: return prettyFormatNumberAverage(totalZeroWins[FROM_CLIENT] + totalZeroWins[FROM_SERVER], duration);
            case Field::RST_AVG: return prettyFormatNumberAverage(totalRsts[FROM_CLIENT] + totalRsts[FROM_SERVER], duration);

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

            case Field::SYN_AVG: return prettyFormatNumberAverage(totalSyns[direction], duration);
            case Field::SYNACK_AVG: return prettyFormatNumberAverage(totalSynAcks[direction], duration);
            case Field::FIN_AVG: return prettyFormatNumberAverage(totalFins[direction], duration);
            case Field::ZWIN_AVG: return prettyFormatNumberAverage(totalZeroWins[direction], duration);
            case Field::RST_AVG: return prettyFormatNumberAverage(totalRsts[direction], duration);

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
            case Field::CT_P95: return connectionTimes.getPercentileStr(0.95);
            case Field::CT_P99: return connectionTimes.getPercentileStr(0.99);
            case Field::CT_TOTAL_P95: return totalConnectionTimes.getPercentileStr(0.95);
            case Field::CT_TOTAL_P99: return totalConnectionTimes.getPercentileStr(0.99);

            case Field::SRT: return prettyFormatNumber(totalNumSrts);
            case Field::SRT_P95: return srts.getPercentileStr(0.95);
            case Field::SRT_P99: return srts.getPercentileStr(0.99);
            case Field::SRT_MAX: return srts.getPercentileStr(1);
            case Field::SRT_TOTAL_P95: return totalSrts.getPercentileStr(0.95);
            case Field::SRT_TOTAL_P99: return totalSrts.getPercentileStr(0.99);
            case Field::SRT_TOTAL_MAX: return totalSrts.getPercentileStr(1);

            case Field::DS_P95: return prettyFormatBytes(requestSizes.getPercentile(0.95));
            case Field::DS_P99: return prettyFormatBytes(requestSizes.getPercentile(0.99));
            case Field::DS_MAX: return prettyFormatBytes(requestSizes.getPercentile(1));
            case Field::DS_TOTAL_P95: return prettyFormatBytes(totalRequestSizes.getPercentile(0.95));
            case Field::DS_TOTAL_P99: return prettyFormatBytes(totalRequestSizes.getPercentile(0.99));
            case Field::DS_TOTAL_MAX: return prettyFormatBytes(totalRequestSizes.getPercentile(1));

            case Field::TOP_CLIENT_IPS_IP: return getTopClientIpsKey(index);
            case Field::TOP_CLIENT_IPS_BYTES: return getTopClientIpsValue(TrafficStatsTcp::BYTES, index);
            case Field::TOP_CLIENT_IPS_PKTS: return getTopClientIpsValue(TrafficStatsTcp::PKTS, index);

            case Field::FQDN: return getFqdn();
            case Field::IP: return getSrvIp().getAddrStr();
            case Field::PORT: return std::to_string(getSrvPort());

            case Field::CONN_RATE: return std::to_string(numConnections);
            case Field::CLOSE_RATE: return std::to_string(closes);
            case Field::SRT_RATE: return prettyFormatNumber(srts.getCount());

            case Field::CONN_AVG: return prettyFormatNumberAverage(totalConnections, duration);
            case Field::CLOSE_AVG: return prettyFormatNumberAverage(totalCloses, duration);
            case Field::SRT_AVG: return prettyFormatNumberAverage(totalNumSrts, duration);
            default: break;
        }
    }
    return Flow::getFieldStr(field, direction, duration, index);
}

auto TcpAggregatedFlow::addAggregatedFlow(Flow const* flow) -> void
{
    Flow::addFlow(flow);

    auto const* tcpFlow = static_cast<const TcpAggregatedFlow*>(flow);
    for (auto const& sourceIt : tcpFlow->sourceIpToStats) {
        auto* stats = &sourceIpToStats[sourceIt.first];
        stats->bytes += sourceIt.second.bytes;
        stats->pkts += sourceIt.second.pkts;
    }

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
    totalNumSrts += tcpFlow->totalNumSrts;

    connectionTimes.addPoints(tcpFlow->connectionTimes);
    totalConnectionTimes.addPoints(tcpFlow->totalConnectionTimes);
    srts.addPoints(tcpFlow->srts);
    totalSrts.addPoints(tcpFlow->srts);
    requestSizes.addPoints(tcpFlow->requestSizes);
}

auto TcpAggregatedFlow::resetFlow(bool resetTotal) -> void
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
        totalNumSrts = 0;

        totalSrts.reset();
        totalConnectionTimes.reset();
        totalRequestSizes.reset();

        sourceIpToStats.clear();
    }

    connectionTimes.reset();
    srts.reset();
    requestSizes.reset();
}

auto TcpAggregatedFlow::failConnection() -> void
{
    failedConnections++;
};

auto TcpAggregatedFlow::mergePercentiles() -> void
{
    srts.merge();
    totalSrts.merge();
    connectionTimes.merge();
    totalConnectionTimes.merge();
    requestSizes.merge();
    totalRequestSizes.merge();
}

auto TcpAggregatedFlow::ongoingConnection() -> void
{
    activeConnections++;
};

auto TcpAggregatedFlow::openConnection(int connectionTime) -> void
{
    connectionTimes.addPoint(connectionTime);
    totalConnectionTimes.addPoint(connectionTime);
    numConnections++;
    activeConnections++;
    totalConnections++;
};

auto TcpAggregatedFlow::addCltPacket(IPAddress const& cltIp, int numBytes) -> void
{
    auto* stats = &sourceIpToStats[cltIp];
    stats->bytes += numBytes;
    stats->pkts++;
};

auto TcpAggregatedFlow::addSrt(int srt, int dataSize) -> void
{
    srts.addPoint(srt);
    totalSrts.addPoint(srt);
    requestSizes.addPoint(dataSize);
    numSrts++;
    totalNumSrts++;
};

auto TcpAggregatedFlow::closeConnection() -> void
{
    closes++;
    totalCloses++;
    activeConnections--;
};

auto TcpAggregatedFlow::getStatsdMetrics() const -> std::vector<std::string>
{
    std::vector<std::string> lst;
    DogFood::Tags tags = DogFood::Tags({ { "fqdn", getFqdn() },
        { "ip", getSrvIp().getAddrStr() },
        { "port", std::to_string(getSrvPort()) } });
    for (auto& i : srts.getPoints()) {
        lst.push_back(DogFood::Metric("flowstats.tcp.srt", i,
            DogFood::Histogram, 1, tags));
    }
    for (auto& i : connectionTimes.getPoints()) {
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
