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
    Collector(FlowstatsConfiguration const& conf, DisplayConfiguration const& displayConf)
        : conf(conf)
        , displayConf(displayConf) {};
    virtual ~Collector() = default;

    virtual auto processPacket(Tins::Packet const& pdu) -> void = 0;
    virtual auto advanceTick(timeval now) -> void {};
    virtual auto resetMetrics() -> void {};
    virtual auto getMetrics() -> std::vector<std::string>
    {
        std::vector<std::string> empty;
        return empty;
    };

    auto sendMetrics() -> void;
    virtual auto mergePercentiles() -> void {};

    virtual auto toString() -> std::string = 0;
    virtual auto getProtocol() -> CollectorProtocol = 0;

    auto getDisplayPairs() { return displayPairs; };
    auto outputStatus(int duration) -> CollectorOutput;
    auto updateDisplayType(int displayIndex) -> void;

protected:
    [[nodiscard]] virtual auto getAggregatedPairs() const -> std::vector<AggregatedPairPointer> { return {}; };
    auto fillOutputs(std::vector<AggregatedPairPointer> const& aggregatedPairs,
        std::vector<std::string>* keyLines,
        std::vector<std::string>* valueLines, int duration);

    auto outputFlow(Flow const* flow,
        std::vector<std::string>* keyLines,
        std::vector<std::string>* valueLines,
        int duration, int position) const -> void;

    virtual auto getFlowFormatter() -> FlowFormatter { return flowFormatter; };
    FlowFormatter flowFormatter;

    auto getDataMutex() -> std::mutex* { return &dataMutex; };

    FlowstatsConfiguration const& conf;
    DisplayConfiguration const& displayConf;
    Flow* totalFlow = nullptr;
    std::vector<DisplayPair> displayPairs;

private:
    std::mutex dataMutex;
};
} // namespace flowstats
