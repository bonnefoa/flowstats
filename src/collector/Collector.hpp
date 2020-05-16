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
    virtual ~Collector();

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
    auto getSortFields() { return sortFields; };
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

    auto getDataMutex() -> std::mutex* { return &dataMutex; };
    auto getFlowFormatter() -> FlowFormatter& { return flowFormatter; };
    auto getFlowFormatter() const -> FlowFormatter const& { return flowFormatter; };
    [[nodiscard]] auto getDisplayConf() const -> DisplayConfiguration const& { return displayConf; };
    [[nodiscard]] auto getFlowstatsConfiguration() const -> FlowstatsConfiguration const& { return conf; };

    auto setDisplayKeys(std::vector<Field> const& keys) -> void { getFlowFormatter().setDisplayKeys(keys); };
    auto setDisplayPairs(std::vector<DisplayPair> pairs) -> void { displayPairs = std::move(pairs); };
    auto fillSortFields() -> void;
    auto setTotalFlow(Flow* flow) -> void { totalFlow = flow; };

private:
    std::mutex dataMutex;
    FlowFormatter flowFormatter;
    FlowstatsConfiguration const& conf;
    DisplayConfiguration const& displayConf;
    Flow* totalFlow = nullptr;
    std::vector<DisplayPair> displayPairs;
    std::vector<Field> sortFields;
};
} // namespace flowstats
