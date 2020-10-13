#pragma once

#include "Collector.hpp"
#include "Configuration.hpp"
#include "Screen.hpp"
#include "Stats.hpp"
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
        , shouldStop(shouldStop)
    {
        lastPcapStat.ps_recv = 0;
    };
    virtual ~PktSource() = default;

    auto updateScreen(timeval currentTime) -> void;
    [[nodiscard]] auto getCaptureStatus() -> std::optional<CaptureStat>;
    [[nodiscard]] auto getLocalIps() -> std::vector<Tins::IPv4Address>;

    auto analyzeLiveTraffic() -> int;
    auto analyzePcapFile() -> int;
    auto processPacketSource(Tins::Packet const& packet) -> void;

private:

    Screen* screen;
    FlowstatsConfiguration const& conf;
    std::vector<Collector*> const& collectors;
    std::atomic_bool* shouldStop;

    timeval lastUpdate = {};
    pcap_stat lastPcapStat = {};

    auto getLiveDevice() -> Tins::Sniffer*;
    Tins::Sniffer* liveDevice = nullptr;
};

} // namespace flowstats
