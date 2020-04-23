#pragma once

#include "AggregatedFlow.hpp"
#include "CollectorOutput.hpp"
#include "Configuration.hpp"
#include "DogFood.hpp"
#include "Flow.hpp"
#include "FlowFormatter.hpp"
#include "Utils.hpp"
#include <fmt/format.h>
#include <map>
#include <mutex>
#include <stdio.h>
#include <sys/time.h>

namespace flowstats {

enum CollectorProtocol {
    TCP,
    DNS,
    SSL,
};
auto collectorProtocolToString(CollectorProtocol proto) -> std::string;

class Collector {
public:
    Collector(FlowstatsConfiguration& conf, DisplayConfiguration& displayConf)
        : conf(conf)
        , displayConf(displayConf) {};
    virtual ~Collector() = default;

    virtual void processPacket(const Tins::Packet& pdu)
        = 0;
    virtual void advanceTick(timeval now) {};
    virtual void resetMetrics() {};
    virtual auto getMetrics() -> std::vector<std::string>
    {
        std::vector<std::string> empty;
        return empty;
    };
    void sendMetrics();
    virtual void mergePercentiles() {};

    virtual auto toString() -> std::string = 0;
    virtual auto getProtocol() -> CollectorProtocol = 0;
    auto getDisplayPairs() -> std::vector<DisplayPair>&
    {
        return displayPairs;
    };

    auto outputStatus(int duration) -> CollectorOutput;
    auto updateDisplayType(int displayIndex) -> void;

protected:
    virtual auto getAggregatedPairs() -> std::vector<AggregatedPairPointer> const { return {}; };

    void fillOutputs(const std::vector<AggregatedPairPointer>& aggregatedPairs,
        std::vector<std::string>& keyLines,
        std::vector<std::string>& valueLines, int duration);

    void outputFlow(Flow* flow,
        std::vector<std::string>& keyLines,
        std::vector<std::string>& valueLines, int duration,
        int position);

    virtual FlowFormatter getFlowFormatter() { return flowFormatter; };
    FlowFormatter flowFormatter;

    virtual std::mutex* getDataMutex() { return &dataMutex; };

    FlowstatsConfiguration& conf;
    DisplayConfiguration& displayConf;
    Flow* totalFlow;
    std::vector<DisplayPair> displayPairs;

private:
    std::mutex dataMutex;
};
}
