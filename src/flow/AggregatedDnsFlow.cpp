#include "AggregatedDnsFlow.hpp"
#include "FlowFormatter.hpp"
#include <algorithm>
#include <fmt/format.h>

namespace flowstats {

auto AggregatedDnsFlow::getTopClientIps() -> std::vector<std::pair<int, int>>
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

auto AggregatedDnsFlow::getTopClientIpsStr() -> std::string
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

void AggregatedDnsFlow::fillValues(std::map<std::string, std::string>& values,
    Direction direction, int duration)
{
    Flow::fillValues(values, direction, duration);
    if (fqdn == "Total") {
        if (direction == FROM_SERVER) {
            return;
        }
        values["fqdn"] = fqdn;
        values["ip"] = "-";
        values["port"] = "-";
        values["proto"] = "-";
        values["type"] = "-";

        values["timeouts_s"] = std::to_string(timeouts);
        values["timeouts"] = std::to_string(totalTimeouts);
        values["req"] = prettyFormatNumber(totalQueries);
        values["req_s"] = prettyFormatNumber(queries);

        values["srt"] = prettyFormatNumber(totalSrt);
        values["srt_s"] = prettyFormatNumber(numSrt);
        values["srt95"] = srts.getPercentileStr(0.95);
        values["srt99"] = srts.getPercentileStr(0.99);

        values["trunc"] = std::to_string(totalTruncated);
        values["rcrd_rsp"] = "-";

        values["top_client_ips"] = getTopClientIpsStr();
        return;
    }

    if (direction == FROM_CLIENT) {
        values["fqdn"] = fqdn;
        values["proto"] = flowId.isTcp ? "Tcp" : "Udp";
        values["type"] = dnsTypeToString(dnsType);
        values["ip"] = getSrvIp().to_string();
        values["timeouts_s"] = std::to_string(timeouts);
        values["timeouts"] = std::to_string(totalTimeouts);
        values["port"] = std::to_string(getSrvPort());
        values["req"] = prettyFormatNumber(totalQueries);
        values["req_s"] = prettyFormatNumber(queries);
        values["top_client_ips"] = getTopClientIpsStr();

        values["srt"] = prettyFormatNumber(totalSrt);
        values["srt_s"] = prettyFormatNumber(numSrt);
        values["srt95"] = srts.getPercentileStr(0.95);
        values["srt99"] = srts.getPercentileStr(0.99);

        values["trunc"] = std::to_string(totalTruncated);
        if (totalQueries > 0) {
            values["rcrd_rsp"] = std::to_string(totalRecords / totalQueries);
        }
    } else {
        if (fqdn.size() > FQDN_SIZE) {
            values["fqdn"] = fqdn.substr(FQDN_SIZE);
        }
    }
}

void AggregatedDnsFlow::addFlow(Flow* flow)
{
    Flow::addFlow(flow);

    auto* dnsFlow = dynamic_cast<DnsFlow*>(flow);
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
        srts.addPoint(getTimevalDeltaMs(dnsFlow->m_StartTimestamp,
            dnsFlow->m_EndTimestamp));
        totalSrt++;
        numSrt++;
    }
}

void AggregatedDnsFlow::addAggregatedFlow(Flow* flow)
{
    Flow::addFlow(flow);

    auto* dnsFlow = dynamic_cast<AggregatedDnsFlow*>(flow);
    queries += dnsFlow->queries;
    truncated += dnsFlow->truncated;
    records += dnsFlow->records;
    timeouts += !dnsFlow->timeouts;

    std::map<int, int>::iterator it;
    for (it = dnsFlow->sourceIps.begin(); it != dnsFlow->sourceIps.end(); it++) {
        sourceIps[it->first] += it->second;
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
