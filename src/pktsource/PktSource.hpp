#pragma once

#include "Collector.hpp"
#include "Configuration.hpp"
#include "Screen.hpp"
#include <pcap/pcap.h>
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

    auto updateScreen(int currentTime) -> void;
    [[nodiscard]] auto getCaptureStatus() -> std::array<std::string, 2>;
    [[nodiscard]] auto getLocalIps() -> std::vector<Tins::IPv4Address>;

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
    pcap_stat lastPcapStat = {};

    auto getLiveDevice() -> Tins::Sniffer*;
    Tins::Sniffer* liveDevice = nullptr;
};

} // namespace flowstats
