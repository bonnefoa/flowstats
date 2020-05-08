#include "Collector.hpp"
#include "FlowId.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <ostream>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>

namespace flowstats {

void Collector::sendMetrics()
{
    auto agentConf = conf.getAgentConf();
    if (!agentConf.has_value()) {
        return;
    }
    std::vector<std::string> metrics = getMetrics();
    for (auto& metric : metrics) {
        spdlog::debug("Sending {}", metric);
        DogFood::Send(metric, agentConf.value());
    }
}

auto Collector::outputFlow(Flow const* flow,
    std::vector<std::string>* keyLines,
    std::vector<std::string>* valueLines,
    int duration, int position) const -> void
{
    for (int j = FROM_CLIENT; j <= FROM_SERVER; ++j) {
        auto direction = static_cast<Direction>(j);
        std::map<Field, std::string> values;
        flow->fillValues(values, direction, duration);
        if (position == -1) {
            keyLines->push_back(flowFormatter.outputKey(values));
            valueLines->push_back(flowFormatter.outputValue(values));
        } else {
            keyLines->at(position) = flowFormatter.outputKey(values);
            valueLines->at(position++) = flowFormatter.outputValue(values);
        }
    }
}

auto Collector::fillOutputs(std::vector<AggregatedPairPointer> const& aggregatedPairs,
    std::vector<std::string>* keyLines,
    std::vector<std::string>* valueLines, int duration)
{
    FlowFormatter flowFormatter = getFlowFormatter();

    totalFlow->resetFlow(true);

    keyLines->resize(2);
    valueLines->resize(2);

    int i = 0;
    for (auto const& pair : aggregatedPairs) {
        auto* flow = pair.second;
        if (flow->fqdn.find(displayConf.filter) == std::string::npos) {
            continue;
        }
        totalFlow->addAggregatedFlow(pair.second);
        if (i++ <= displayConf.maxResults) {
            outputFlow(flow, keyLines, valueLines, duration, -1);
        }
    }
    outputFlow(totalFlow, keyLines, valueLines, duration, 0);
}

void Collector::updateDisplayType(int displayIndex)
{
    flowFormatter.setDisplayValues(displayPairs[displayIndex].second);
    return;
}

auto Collector::outputStatus(int duration) -> CollectorOutput
{
    std::vector<std::string> valueLines;
    std::vector<std::string> keyLines;

    std::string keyHeaders;
    std::string valueHeaders;

    FlowFormatter flowFormatter = getFlowFormatter();
    flowFormatter.outputHeaders(keyHeaders, valueHeaders);

    const std::lock_guard<std::mutex> lock(*getDataMutex());
    mergePercentiles();
    std::vector<AggregatedPairPointer> tempVector = getAggregatedPairs();
    fillOutputs(tempVector, &keyLines, &valueLines, duration);
    return CollectorOutput(toString(), keyLines, valueLines,
        keyHeaders, valueHeaders, duration);
}

auto collectorProtocolToString(CollectorProtocol proto) -> std::string
{
#define ENUM_TEXT(p) \
    case (p):        \
        return #p;
    switch (proto) {
        ENUM_TEXT(DNS);
        ENUM_TEXT(TCP);
        ENUM_TEXT(SSL);
    }
}

} // namespace flowstats
