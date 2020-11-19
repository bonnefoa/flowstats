#include "DnsAggregatedFlow.hpp"
#include "Field.hpp"
#include "FlowFormatter.hpp"
#include <algorithm>
#include <fmt/format.h>

namespace flowstats {

auto DnsAggregatedFlow::getTopClientIpsKey(int index) const -> std::string
{
    return topClientIps[index].first.getAddrStr();
}

auto DnsAggregatedFlow::getTopClientIpsValue(TrafficStatsDns::TrafficType type, int index) const -> std::string
{
    std::string val;
    auto const& stat = topClientIps[index].second;
    switch (type) {
        case TrafficStatsDns::PKTS:
            return prettyFormatNumber(stat.pkts);
        case TrafficStatsDns::BYTES:
            return prettyFormatNumber(stat.bytes);
        case TrafficStatsDns::REQUESTS:
            return prettyFormatNumber(stat.requests);
        default:
            return "Error";
    }
}

auto DnsAggregatedFlow::getSubfieldSize(Field field) const -> int
{
    switch (field) {
        case Field::TOP_CLIENT_IPS_IP:
        case Field::TOP_CLIENT_IPS_BYTES:
        case Field::TOP_CLIENT_IPS_PKTS:
        case Field::TOP_CLIENT_IPS_REQUESTS:
            return std::min(5, static_cast<int>(sourceIpToStats.size()));
        default:
            return 0;
    }
    return 0;
}

auto DnsAggregatedFlow::prepareSubfields(std::vector<Field> const& subfields) -> void
{
    for (auto field : subfields) {
        if (field == +Field::TOP_CLIENT_IPS_IP) {
            computeTopClientIps(TrafficStatsDns::REQUESTS);
        }
    }
}

auto DnsAggregatedFlow::computeTopClientIps(TrafficStatsDns::TrafficType type) -> void
{
    int size = std::min(5, static_cast<int>(sourceIpToStats.size()));
    topClientIps = std::vector<std::pair<IPAddress, TrafficStatsDns>>(size);

    bool (*sortFun)(std::pair<IPAddress, TrafficStatsDns> const& l,
        std::pair<IPAddress, TrafficStatsDns> const& r)
        = nullptr;
    switch (type) {
        case TrafficStatsDns::PKTS:
            sortFun = [](std::pair<IPAddress, TrafficStatsDns> const& l,
                          std::pair<IPAddress, TrafficStatsDns> const& r) {
                return l.second.pkts > r.second.pkts;
            };
            break;
        case TrafficStatsDns::BYTES:
            sortFun = [](std::pair<IPAddress, TrafficStatsDns> const& l,
                          std::pair<IPAddress, TrafficStatsDns> const& r) {
                return l.second.bytes > r.second.bytes;
            };
            break;
        case TrafficStatsDns::REQUESTS:
            sortFun = [](std::pair<IPAddress, TrafficStatsDns> const& l,
                          std::pair<IPAddress, TrafficStatsDns> const& r) {
                return l.second.requests > r.second.requests;
            };
            break;
    }

    std::partial_sort_copy(sourceIpToStats.begin(), sourceIpToStats.end(),
        topClientIps.begin(), topClientIps.end(), sortFun);
}

auto DnsAggregatedFlow::getFieldStr(Field field, Direction direction, int duration, int index) const -> std::string
{
    if (index > 0) {
        switch (field) {
            case Field::TOP_CLIENT_IPS_IP: return getTopClientIpsKey(index);
            case Field::TOP_CLIENT_IPS_BYTES: return getTopClientIpsValue(TrafficStatsDns::BYTES, index);
            case Field::TOP_CLIENT_IPS_PKTS: return getTopClientIpsValue(TrafficStatsDns::PKTS, index);
            case Field::TOP_CLIENT_IPS_REQUESTS: return getTopClientIpsValue(TrafficStatsDns::REQUESTS, index);
            default: return "";
        }
    }

    auto fqdn = getFqdn();
    if (fqdn == "Total") {
        if (direction == FROM_CLIENT || direction == MERGED) {
            switch (field) {
                case Field::IP:
                case Field::PORT:
                case Field::PROTO:
                case Field::TYPE:
                case Field::RCRD_AVG:
                    return "-";
                default: break;
            }
        }
    }

    if (direction == FROM_CLIENT || direction == MERGED) {
        switch (field) {
            case Field::FQDN: return getFqdn();
            case Field::PROTO: return getTransport()._to_string();
            case Field::TYPE: return dnsTypeToString(dnsType);
            case Field::IP: return getSrvIp().getAddrStr();
            case Field::PORT: return std::to_string(getSrvPort());

            case Field::TOP_CLIENT_IPS_IP: return getTopClientIpsKey(index);
            case Field::TOP_CLIENT_IPS_BYTES: return getTopClientIpsValue(TrafficStatsDns::BYTES, index);
            case Field::TOP_CLIENT_IPS_PKTS: return getTopClientIpsValue(TrafficStatsDns::PKTS, index);
            case Field::TOP_CLIENT_IPS_REQUESTS: return getTopClientIpsValue(TrafficStatsDns::REQUESTS, index);

            case Field::TIMEOUTS: return std::to_string(totalTimeouts);
            case Field::REQ: return prettyFormatNumber(totalQueries);
            case Field::SRT: return prettyFormatNumber(totalNumSrt);

            case Field::TIMEOUTS_AVG: return prettyFormatNumberAverage(totalTimeouts, duration);
            case Field::REQ_AVG: return prettyFormatNumberAverage(totalQueries, duration);
            case Field::SRT_AVG: return prettyFormatNumberAverage(totalNumSrt, duration);

            case Field::TIMEOUTS_RATE: return std::to_string(timeouts);
            case Field::REQ_RATE: return prettyFormatNumber(queries);
            case Field::SRT_RATE: return prettyFormatNumber(numSrt);

            case Field::SRT_P95: return srts.getPercentileStr(0.95);
            case Field::SRT_P99: return srts.getPercentileStr(0.99);
            case Field::SRT_TOTAL_P95: return totalSrts.getPercentileStr(0.95);
            case Field::SRT_TOTAL_P99: return totalSrts.getPercentileStr(0.99);
            case Field::TRUNC: return std::to_string(totalTruncated);
            case Field::RCRD_AVG: return prettyFormatNumberAverage(totalRecords, totalQueries);
            default:
                break;
        }
    }
    return Flow::getFieldStr(field, direction, duration, index);
}

auto DnsAggregatedFlow::addFlow(Flow const* flow) -> void
{
    Flow::addFlow(flow);

    auto const* dnsFlow = static_cast<DnsFlow const*>(flow);
    queries++;
    truncated += dnsFlow->getTruncated();
    records += dnsFlow->getNumberRecords();
    timeouts += !dnsFlow->getHasResponse();

    auto* stats = &sourceIpToStats[dnsFlow->getCltIp()];
    auto cltPos = !flow->getSrvPos();
    stats->bytes += flow->getTotalBytes()[cltPos];
    stats->pkts += flow->getTotalPackets()[cltPos];
    stats->requests++;

    totalQueries++;
    totalTimeouts += !dnsFlow->getHasResponse();
    totalResponses += dnsFlow->getHasResponse();
    if (dnsFlow->getHasResponse()) {
        totalTruncated += dnsFlow->getTruncated();
        totalRecords += dnsFlow->getNumberRecords();
        srts.addPoint(dnsFlow->getDeltaTv());
        totalSrts.addPoint(dnsFlow->getDeltaTv());
        totalNumSrt++;
        numSrt++;
    }
}

auto DnsAggregatedFlow::addAggregatedFlow(Flow const* flow) -> void
{
    Flow::addFlow(flow);

    auto const* dnsFlow = dynamic_cast<const DnsAggregatedFlow*>(flow);
    queries += dnsFlow->queries;
    truncated += dnsFlow->truncated;
    records += dnsFlow->records;
    timeouts += dnsFlow->timeouts;

    for (auto const& sourceIt : dnsFlow->sourceIpToStats) {
        auto* stats = &sourceIpToStats[sourceIt.first];
        stats->bytes += sourceIt.second.bytes;
        stats->pkts += sourceIt.second.pkts;
        stats->requests += sourceIt.second.requests;
    }

    totalQueries += dnsFlow->totalQueries;
    totalTimeouts += dnsFlow->totalTimeouts;
    totalResponses += dnsFlow->totalResponses;
    totalTruncated += dnsFlow->totalTruncated;
    totalRecords += dnsFlow->totalRecords;
    srts.addPoints(dnsFlow->srts);
    totalSrts.addPoints(dnsFlow->srts);
    totalNumSrt += dnsFlow->totalNumSrt;
    numSrt += dnsFlow->numSrt;
}

void DnsAggregatedFlow::resetFlow(bool resetTotal)
{
    Flow::resetFlow(resetTotal);
    srts.reset();
    queries = 0;
    timeouts = 0;
    truncated = 0;
    records = 0;
    numSrt = 0;

    if (resetTotal) {
        totalSrts.reset();
        sourceIpToStats.clear();
        totalQueries = 0;
        totalTimeouts = 0;
        totalTruncated = 0;
        totalRecords = 0;
        totalNumSrt = 0;
    }
}
} // namespace flowstats
