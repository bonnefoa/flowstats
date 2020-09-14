#include "AggregatedDnsFlow.hpp"
#include "Field.hpp"
#include "FlowFormatter.hpp"
#include <algorithm>
#include <fmt/format.h>

namespace flowstats {

auto AggregatedDnsFlow::getTopClientIps() const -> std::vector<std::pair<int, int>>
{
    int size = std::min(5, static_cast<int>(sourceIps.size()));
    std::vector<std::pair<int, int>> topIps(size);
    std::partial_sort_copy(sourceIps.begin(), sourceIps.end(),
        topIps.begin(), topIps.end(),
        [](std::pair<int, int> const& l,
            std::pair<int, int> const& r) {
            return l.second > r.second;
        });
    return topIps;
}

auto AggregatedDnsFlow::getTopClientIpsStr() const -> std::string
{
    auto topIps = getTopClientIps();
    std::vector<std::string> topIpsStr;
    topIpsStr.reserve(topIps.size());
    for (auto& pair : topIps) {
        topIpsStr.push_back(fmt::format("{:<3} {:<" STR(IP_SIZE) "}",
            prettyFormatNumber(pair.second),
            Tins::IPv4Address(pair.first).to_string()));
    }
    return fmt::format("{}", fmt::join(topIpsStr, " "));
}

auto AggregatedDnsFlow::getFieldStr(Field field, Direction direction, int duration) const -> std::string
{
    auto fqdn = getFqdn();
    if (fqdn == "Total") {
        if (direction == FROM_SERVER) {
            return "";
        }
        switch (field) {
            case Field::IP: return "-";
            case Field::PORT: return "-";
            case Field::PROTO: return "-";
            case Field::TYPE: return "-";
            case Field::RCRD_AVG: return "-";
            default: break;
        }
    }

    if (direction == FROM_CLIENT) {
        switch (field) {
            case Field::FQDN: return getFqdn();
            case Field::PROTO: return getTransport()._to_string();
            case Field::TYPE: return dnsTypeToString(dnsType);
            case Field::IP: return getSrvIp();
            case Field::TIMEOUTS_RATE: return std::to_string(timeouts);
            case Field::TIMEOUTS: return std::to_string(totalTimeouts);
            case Field::PORT: return std::to_string(getSrvPort());
            case Field::REQ: return prettyFormatNumber(totalQueries);
            case Field::REQ_RATE: return prettyFormatNumber(queries);
            case Field::REQ_AVG: return prettyFormatNumberAverage(totalQueries, duration);
            case Field::TOP_CLIENT_IPS: return getTopClientIpsStr();
            case Field::SRT: return prettyFormatNumber(totalSrt);
            case Field::SRT_RATE: return prettyFormatNumber(numSrt);
            case Field::SRT_P95: return srts.getPercentileStr(0.95);
            case Field::SRT_P99: return srts.getPercentileStr(0.99);
            case Field::TRUNC: return std::to_string(totalTruncated);
            case Field::RCRD_AVG: return prettyFormatNumberAverage(totalRecords, totalQueries);
            default:
                break;
        }
    }
    return Flow::getFieldStr(field, direction, duration);
}

auto AggregatedDnsFlow::addFlow(Flow const* flow) -> void
{
    Flow::addFlow(flow);

    auto const* dnsFlow = static_cast<DnsFlow const*>(flow);
    queries++;
    truncated += dnsFlow->getTruncated();
    records += dnsFlow->getNumberRecords();
    timeouts += !dnsFlow->getHasResponse();

    sourceIps[dnsFlow->getCltIp()]++;

    totalQueries++;
    totalTimeouts += !dnsFlow->getHasResponse();
    totalResponses += dnsFlow->getHasResponse();
    if (dnsFlow->getHasResponse()) {
        totalTruncated += dnsFlow->getTruncated();
        totalRecords += dnsFlow->getNumberRecords();
        srts.addPoint(dnsFlow->getDeltaTv());
        totalSrt++;
        numSrt++;
    }
}

auto AggregatedDnsFlow::addAggregatedFlow(Flow const* flow) -> void
{
    Flow::addFlow(flow);

    auto const* dnsFlow = dynamic_cast<const AggregatedDnsFlow*>(flow);
    queries += dnsFlow->queries;
    truncated += dnsFlow->truncated;
    records += dnsFlow->records;
    timeouts += dnsFlow->timeouts;

    for (auto it : dnsFlow->sourceIps) {
        sourceIps[it.first] += it.second;
    }

    totalQueries += dnsFlow->totalQueries;
    totalTimeouts += dnsFlow->totalTimeouts;
    totalResponses += dnsFlow->totalResponses;
    totalTruncated += dnsFlow->totalTruncated;
    totalRecords += dnsFlow->totalRecords;
    srts.addPoints(dnsFlow->srts);
    totalSrt += dnsFlow->totalSrt;
    numSrt += dnsFlow->numSrt;
}

auto AggregatedDnsFlow::getStatsdMetrics() const -> std::vector<std::string>
{
    std::vector<std::string> lst;
    DogFood::Tags tags = DogFood::Tags({
        { "fqdn", getFqdn() },
        { "proto", getTransport()._to_string() },
        { "type", dnsTypeToString(dnsType) },
    });
    if (queries) {
        lst.push_back(DogFood::Metric("flowstats.dns.queries", queries,
            DogFood::Counter, 1, tags));
    }
    if (timeouts) {
        lst.push_back(DogFood::Metric("flowstats.dns.timeouts", timeouts, DogFood::Counter, 1, tags));
    }
    if (records) {
        lst.push_back(DogFood::Metric("flowstats.dns.records", int(totalRecords / totalQueries), DogFood::Counter, 1, tags));
    }
    if (truncated) {
        lst.push_back(DogFood::Metric("flowstats.dns.truncated", truncated, DogFood::Counter, 1, tags));
    }
    return lst;
}

void AggregatedDnsFlow::resetFlow(bool resetTotal)
{
    Flow::resetFlow(resetTotal);
    srts.reset();
    queries = 0;
    timeouts = 0;
    truncated = 0;
    records = 0;
    numSrt = 0;

    if (resetTotal) {
        sourceIps.clear();
        totalQueries = 0;
        totalTimeouts = 0;
        totalTruncated = 0;
        totalRecords = 0;
        totalSrt = 0;
    }
}
} // namespace flowstats
