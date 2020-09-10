#include "Collector.hpp"
#include "FlowId.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <ostream>
#include <string>
#include <vector>

namespace flowstats {

void Collector::sendMetrics()
{
    auto agentConf = conf.getAgentConf();
    if (!agentConf.has_value()) {
        return;
    }
    std::vector<std::string> metrics = getStatsdMetrics();
    for (auto& metric : metrics) {
        SPDLOG_DEBUG("Sending {}", metric);
        DogFood::Send(metric, agentConf.value());
    }
}

auto Collector::outputFlow(Flow const* flow,
    std::vector<std::string>* keyLines,
    std::vector<std::string>* valueLines,
    int position, int duration) const -> void
{
    for (int j = FROM_CLIENT; j <= FROM_SERVER; ++j) {
        auto direction = static_cast<Direction>(j);
        std::map<Field, std::string> values;
        flow->fillValues(&values, direction, duration);
        if (position == -1) {
            keyLines->push_back(flowFormatter.outputKey(values));
            valueLines->push_back(flowFormatter.outputValue(values));
        } else {
            keyLines->at(position) = flowFormatter.outputKey(values);
            valueLines->at(position++) = flowFormatter.outputValue(values);
        }
    }
}

auto Collector::fillOutputs(std::vector<Flow const*> const& aggregatedFlows,
    std::vector<std::string>* keyLines,
    std::vector<std::string>* valueLines,
    int duration)
{
    FlowFormatter flowFormatter = getFlowFormatter();

    totalFlow->resetFlow(true);

    keyLines->resize(2);
    valueLines->resize(2);

    int i = 0;
    for (auto const* flow : aggregatedFlows) {
        if (!displayConf.filter.empty()) {
            if (flow->getFqdn().find(displayConf.filter) == std::string::npos) {
                continue;
            }
        }
        totalFlow->addAggregatedFlow(flow);
        if (i++ <= displayConf.maxResults) {
            outputFlow(flow, keyLines, valueLines, -1, duration);
        }
    }
    outputFlow(totalFlow, keyLines, valueLines, 0, duration);
}

auto Collector::fillSortFields() -> void
{
    auto const& displayKeys = flowFormatter.getDisplayKeys();
    for (auto const& keyField : displayKeys) {
        if (fieldToSortable(keyField)) {
            sortFields.push_back(keyField);
        }
    }
    for (auto const& pair : displayPairs) {
        for (auto const& valueField : pair.second) {
            if (fieldToSortable(valueField)) {
                sortFields.push_back(valueField);
            }
        }
    }
}

auto Collector::getSortFun(Field field) const -> sortFlowFun
{
    switch (field) {
    case Field::FQDN:
        return &Flow::sortByFqdn;
    case Field::IP:
        return &Flow::sortByIp;
    case Field::PORT:
        return &Flow::sortByPort;
    case Field::BYTES_RATE:
        return &Flow::sortByBytes;
    case Field::BYTES:
        return &Flow::sortByTotalBytes;
    case Field::PKTS_RATE:
        return &Flow::sortByPackets;
    case Field::PKTS:
        return &Flow::sortByTotalPackets;
    default:
        return nullptr;
    }
}

auto Collector::mergePercentiles() -> void
{
    for (auto& i : aggregatedMap) {
        i.second->mergePercentiles();
    }
}

auto Collector::resetMetrics() -> void
{
    const std::lock_guard<std::mutex> lock(dataMutex);
    for (auto& pair : aggregatedMap) {
        pair.second->resetFlow(false);
    }
}

auto Collector::getStatsdMetrics() const -> std::vector<std::string>
{
    std::vector<std::string> res;
    for (auto const& pair : aggregatedMap) {
        auto const* val = pair.second;
        auto statsdMetrics = val->getStatsdMetrics();
        res.insert(res.end(), statsdMetrics.begin(), statsdMetrics.end());
    }
    return res;
}

auto Collector::outputStatus(time_t duration) -> CollectorOutput
{
    std::vector<std::string> valueLines;
    std::vector<std::string> keyLines;

    FlowFormatter flowFormatter = getFlowFormatter();
    auto pairHeaders = flowFormatter.outputHeaders();

    const std::lock_guard<std::mutex> lock(dataMutex);
    mergePercentiles();
    std::vector<Flow const*> tempVector = getAggregatedFlows();
    fillOutputs(tempVector, &keyLines, &valueLines, duration);
    return CollectorOutput(toString(), keyLines, valueLines,
        pairHeaders.first, pairHeaders.second, duration);
}

auto Collector::getAggregatedFlows() const -> std::vector<Flow const*>
{
    std::vector<Flow const*> tempVector;
    auto aggregatedMap = getAggregatedMap();
    tempVector.reserve(aggregatedMap.size());
    for (auto const& pair : aggregatedMap) {
        tempVector.push_back(pair.second);
    }
    SPDLOG_INFO("Got {} {} flows", tempVector.size(), toString());
    // TODO Merge percentiles?
    auto sortFun = getSortFun(selectedSortField);
    std::sort(tempVector.begin(), tempVector.end(),
        [&](Flow const* left, Flow const* right) {
            if (left == nullptr || right == nullptr) {
                return false;
            }
            if (reversedSort) {
                return sortFun(right, left);
            } else {
                return sortFun(left, right);
            }
        });
    return tempVector;
}

Collector::~Collector()
{
    delete totalFlow;
    for (auto const& pair : aggregatedMap) {
        delete pair.second;
    }
}

} // namespace flowstats
