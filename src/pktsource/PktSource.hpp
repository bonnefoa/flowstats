#pragma once

#include "Collector.hpp"
#include "Configuration.hpp"
#include "Screen.hpp"
#include <tins/ip_address.h>
#include <tins/sniffer.h>

namespace flowstats {

auto listInterfaces() -> void;

class PktSource {
public:
    PktSource(Screen* screen,
        FlowstatsConfiguration const& conf,
        const std::vector<Collector*>& collectors,
        std::atomic_bool* shouldStop)
        : screen(screen)
        , conf(conf)
        , collectors(collectors)
        , shouldStop(shouldStop) {};
    virtual ~PktSource() = default;

    auto getLocalIps() -> std::vector<Tins::IPv4Address>;
    auto updateScreen(int currentTime) -> void;
    auto analyzeLiveTraffic() -> int;
    auto analyzePcapFile() -> int;

private:
    auto processPacketSource(Tins::Packet const& packet) -> void;

    Screen* screen;
    FlowstatsConfiguration const& conf;
    std::vector<Collector*> const& collectors;
    std::atomic_bool* shouldStop;

    int lastUpdate = 0;
    int lastTs = 0;

    auto getLiveDevice() -> Tins::Sniffer*;
};

} // namespace flowstats
