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

auto Collector::buildTotalFlow(std::vector<Flow const*> const& aggregatedFlows) -> void
{
    totalFlow->resetFlow(true);
    for (auto const* flow : aggregatedFlows) {
        totalFlow->addAggregatedFlow(flow);
    }
}

auto Collector::fillSortFields() -> void
{
    for (auto const& pair : displayFieldValues) {
        for (auto const& field : pair.getFields()) {
            if (fieldToSortable(field)) {
                sortFields.push_back(field);
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
    auto flowFormatter = getFlowFormatter();
    auto headers = flowFormatter.outputHeaders(displayConf);

    const std::lock_guard<std::mutex> lock(dataMutex);
    mergePercentiles();
    std::vector<Flow const*> aggregatedFlows = getAggregatedFlows();

    buildTotalFlow(aggregatedFlows);
    auto bodyLines = flowFormatter.outputFlow(totalFlow,
        aggregatedFlows, duration, displayConf);
    return CollectorOutput(toString(), headers, bodyLines);
}

auto Collector::getAggregatedFlows() const -> std::vector<Flow const*>
{
    std::vector<Flow const*> tempVector;
    auto aggregatedMap = getAggregatedMap();
    tempVector.reserve(aggregatedMap.size());
    for (auto const& pair : aggregatedMap) {
        auto* flow = pair.second;
        auto filter = displayConf.getFilter();
        if (!filter.empty()) {
            if (flow->getFqdn().find(filter) == std::string::npos) {
                continue;
            }
        }
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
