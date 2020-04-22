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

class Collector {
public:
    Collector(FlowstatsConfiguration& conf, DisplayConfiguration& displayConf)
        : conf(conf)
        , displayConf(displayConf) {};
    virtual ~Collector() {}

    virtual void processPacket(Tins::Packet& pdu) = 0;
    virtual std::string getFlowName() = 0;
    virtual void advanceTick(timeval now) {};
    virtual void resetMetrics() {};
    virtual std::vector<std::string> getMetrics()
    {
        std::vector<std::string> empty;
        return empty;
    };
    void sendMetrics();
    virtual void mergePercentiles() {};

    virtual std::string toString() = 0;
    virtual Tins::PDU::PDUType getProtocol() = 0;
    std::vector<DisplayPair>& getDisplayPairs()
    {
        return displayPairs;
    };

    CollectorOutput outputStatus(int duration);
    void updateDisplayType(int displayIndex);

protected:
    virtual std::vector<AggregatedPairPointer> getAggregatedPairs() { return {}; };
    virtual std::vector<Flow*> getFlows() = 0;

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

    std::mutex dataMutex;
    FlowstatsConfiguration& conf;
    DisplayConfiguration& displayConf;
    Flow* totalFlow;
    std::vector<DisplayPair> displayPairs;

private:
};
}
