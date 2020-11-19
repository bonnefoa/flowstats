#pragma once

#include "AggregatedKeys.hpp"
#include "CollectorOutput.hpp"
#include "Configuration.hpp"
#include "DisplayType.hpp"
#include "Flow.hpp"
#include "FlowFormatter.hpp"
#include "Utils.hpp"
#include <fmt/format.h>
#include <map>
#include <mutex>
#include <sys/time.h>

namespace flowstats {

// NOLINTNEXTLINE
BETTER_ENUM(CollectorProtocol, char,
    TCP,
    DNS,
    SSL);

class Collector {
public:
    Collector(FlowstatsConfiguration const& conf, DisplayConfiguration const& displayConf)
        : conf(conf)
        , displayConf(displayConf) {};
    virtual ~Collector();

    virtual auto processPacket(Tins::Packet const& pdu,
        FlowId const& flowId,
        Tins::IP const* ip,
        Tins::IPv6 const* ipv6,
        Tins::TCP const* tcp,
        Tins::UDP const* udp) -> void
        = 0;
    virtual auto advanceTick(timeval now) -> void {};
    auto resetMetrics() -> void;

    auto mergePercentiles() -> void;

    [[nodiscard]] virtual auto toString() const -> std::string = 0;
    [[nodiscard]] virtual auto getProtocol() const -> CollectorProtocol = 0;

    [[nodiscard]] auto getDisplayFieldValues() const { return displayFieldValues; };
    [[nodiscard]] auto getSortFields() const { return sortFields; };
    typedef bool (*sortFlowFun)(Flow const*, Flow const*);
    [[nodiscard]] virtual auto getSortFun(Field field) const -> sortFlowFun;

    [[nodiscard]] auto outputStatus(time_t duration) -> CollectorOutput;

    auto updateDisplayType(int displayIndex) -> void { flowFormatter.setDisplayValues(displayFieldValues[displayIndex]); };

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

    [[nodiscard]] auto getFlowFormatterPtr() -> FlowFormatter* { return &flowFormatter; };
    [[nodiscard]] auto getFlowFormatter() -> FlowFormatter& { return flowFormatter; };
    [[nodiscard]] auto getFlowFormatter() const -> FlowFormatter const& { return flowFormatter; };

protected:
    auto buildTotalFlow(std::vector<Flow const*> const& aggregatedFlows) -> void;

    [[nodiscard]] auto getDataMutex() -> std::mutex* { return &dataMutex; };
    [[nodiscard]] auto getDisplayConf() const -> DisplayConfiguration const& { return displayConf; };
    [[nodiscard]] auto getFlowstatsConfiguration() const -> FlowstatsConfiguration const& { return conf; };

    auto setDisplayPairs(std::vector<DisplayFieldValues> pairs) -> void { displayFieldValues = std::move(pairs); };
    auto fillSortFields() -> void;
    auto setTotalFlow(Flow* flow) -> void { totalFlow = flow; };

private:
    std::mutex dataMutex;
    FlowFormatter flowFormatter;
    FlowstatsConfiguration const& conf;
    DisplayConfiguration const& displayConf;
    Flow* totalFlow = nullptr;
    std::vector<DisplayFieldValues> displayFieldValues;
    std::vector<Field> sortFields;
    Field selectedSortField = Field::FQDN;
    bool reversedSort = false;
    std::unordered_map<AggregatedKey, Flow*, std::hash<AggregatedKey>> aggregatedMap;
};
} // namespace flowstats
