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
        values[Field::RCRD_RSP] = "-";

        values[Field::TOP_CLIENT_IPS] = getTopClientIpsStr();
        return;
    }

    if (direction == FROM_CLIENT) {
        values[Field::FQDN] = fqdn;
        values[Field::PROTO] = flowId.isTcp ? "Tcp" : "Udp";
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
            values[Field::RCRD_RSP] = std::to_string(totalRecords / totalQueries);
        }
    } else {
        if (fqdn.size() > FQDN_SIZE) {
            values[Field::FQDN] = fqdn.substr(FQDN_SIZE);
        }
    }
}

auto AggregatedDnsFlow::addFlow(const Flow* flow) -> void
{
    Flow::addFlow(flow);

    auto dnsFlow = dynamic_cast<const DnsFlow*>(flow);
    queries++;
    truncated += dnsFlow->truncated;
    records += dnsFlow->numberRecords;
    timeouts += !dnsFlow->hasResponse;

    sourceIps[dnsFlow->getCltIp()]++;

    totalQueries++;
    totalTimeouts += !dnsFlow->hasResponse;
    totalResponses += dnsFlow->hasResponse;
    if (dnsFlow->hasResponse) {
        totalTruncated += dnsFlow->truncated;
        totalRecords += dnsFlow->numberRecords;
        srts.addPoint(getTimevalDeltaMs(dnsFlow->startTv,
            dnsFlow->endTv));
        totalSrt++;
        numSrt++;
    }
}

auto AggregatedDnsFlow::addAggregatedFlow(const Flow* flow) -> void
{
    Flow::addFlow(flow);

    auto* dnsFlow = dynamic_cast<const AggregatedDnsFlow*>(flow);
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
