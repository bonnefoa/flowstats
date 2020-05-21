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

auto AggregatedDnsFlow::fillValues(std::map<Field, std::string>& values,
    Direction direction, int duration) const -> void
{
    Flow::fillValues(values, direction, duration);
    auto fqdn = getFqdn();
    if (fqdn == "Total") {
        if (direction == FROM_SERVER) {
            return;
        }
        values[Field::FQDN] = fqdn;
        values[Field::IP] = "-";
        values[Field::PORT] = "-";
        values[Field::PROTO] = "-";
        values[Field::TYPE] = "-";

        values[Field::TIMEOUTS_RATE] = std::to_string(timeouts);
        values[Field::TIMEOUTS] = std::to_string(totalTimeouts);
        values[Field::REQ] = prettyFormatNumber(totalQueries);
        values[Field::REQ_RATE] = prettyFormatNumber(queries);

        values[Field::SRT] = prettyFormatNumber(totalSrt);
        values[Field::SRT_RATE] = prettyFormatNumber(numSrt);
        values[Field::SRT_P95] = srts.getPercentileStr(0.95);
        values[Field::SRT_P99] = srts.getPercentileStr(0.99);

        values[Field::TRUNC] = std::to_string(totalTruncated);
        values[Field::RCRD_AVG] = "-";

        values[Field::TOP_CLIENT_IPS] = getTopClientIpsStr();
        return;
    }

    if (direction == FROM_CLIENT) {
        values[Field::FQDN] = fqdn;
        values[Field::PROTO] = getTransport()._to_string();
        values[Field::TYPE] = dnsTypeToString(dnsType);
        values[Field::IP] = getSrvIp().to_string();
        values[Field::TIMEOUTS_RATE] = std::to_string(timeouts);
        values[Field::TIMEOUTS] = std::to_string(totalTimeouts);
        values[Field::PORT] = std::to_string(getSrvPort());
        values[Field::REQ] = prettyFormatNumber(totalQueries);
        values[Field::REQ_RATE] = prettyFormatNumber(queries);
        values[Field::TOP_CLIENT_IPS] = getTopClientIpsStr();

        values[Field::SRT] = prettyFormatNumber(totalSrt);
        values[Field::SRT_RATE] = prettyFormatNumber(numSrt);
        values[Field::SRT_P95] = srts.getPercentileStr(0.95);
        values[Field::SRT_P99] = srts.getPercentileStr(0.99);

        values[Field::TRUNC] = std::to_string(totalTruncated);
        if (totalQueries > 0) {
            values[Field::RCRD_AVG] = std::to_string(totalRecords / totalQueries);
        }
    } else {
        if (fqdn.size() > FQDN_SIZE) {
            values[Field::FQDN] = fqdn.substr(FQDN_SIZE);
        }
    }
}

auto AggregatedDnsFlow::addFlow(Flow const* flow) -> void
{
    Flow::addFlow(flow);

    auto const* dnsFlow = dynamic_cast<DnsFlow const*>(flow);
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
    timeouts += !dnsFlow->timeouts;

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
