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

    virtual auto processPacket(Tins::Packet const& pdu,
        FlowId const& flowId,
        Tins::IP const& ip,
        Tins::TCP const* tcp,
        Tins::UDP const* udp) -> void
        = 0;
    virtual auto advanceTick(timeval now) -> void {};
    auto resetMetrics() -> void;

    [[nodiscard]] auto getStatsdMetrics() const -> std::vector<std::string>;
    auto sendMetrics() -> void;
    auto mergePercentiles() -> void;

    [[nodiscard]] virtual auto toString() const -> std::string = 0;
    [[nodiscard]] virtual auto getProtocol() const -> CollectorProtocol = 0;

    [[nodiscard]] auto getDisplayPairs() const { return displayPairs; };
    [[nodiscard]] auto getSortFields() const { return sortFields; };
    typedef bool (*sortFlowFun)(Flow const*, Flow const*);
    [[nodiscard]] virtual auto getSortFun(Field field) const -> sortFlowFun;

    [[nodiscard]] auto outputStatus(int duration) -> CollectorOutput;

    auto updateDisplayType(int displayIndex) -> void { flowFormatter.setDisplayValues(displayPairs[displayIndex].second); };

    auto updateSort(int sortIndex, bool reversed) -> void
    {
        selectedSortField = sortFields.at(sortIndex);
        reversedSort = reversed;
    };

    auto setSortField(Field field, bool reversed) -> void
    {
        selectedSortField = field;
        reversedSort = reversed;
    };

    [[nodiscard]] auto getAggregatedMap() const { return aggregatedMap; }
    [[nodiscard]] auto getAggregatedMap() { return &aggregatedMap; }
    [[nodiscard]] auto getAggregatedFlows() const -> std::vector<Flow const*>;

protected:
    auto fillOutputs(std::vector<Flow const*> const& aggregatedFlows,
        std::vector<std::string>* keyLines,
        std::vector<std::string>* valueLines);

    auto outputFlow(Flow const* flow,
        std::vector<std::string>* keyLines,
        std::vector<std::string>* valueLines,
        int position) const -> void;

    [[nodiscard]] auto getDataMutex() -> std::mutex* { return &dataMutex; };
    [[nodiscard]] auto getFlowFormatter() -> FlowFormatter& { return flowFormatter; };
    [[nodiscard]] auto getFlowFormatter() const -> FlowFormatter const& { return flowFormatter; };
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
    Field selectedSortField = Field::FQDN;
    bool reversedSort = false;
    std::map<AggregatedKey, Flow*> aggregatedMap;
};
} // namespace flowstats
