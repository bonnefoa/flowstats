#include "PktSource.hpp"
#include "Utils.hpp"
#include <network_interface.h>
#include <spdlog/spdlog.h>

#include <utility>

namespace flowstats {

/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
    const std::vector<Tins::NetworkInterface> ifaces = Tins::NetworkInterface::all();

    printf("\nNetwork interfaces:\n");
    for (auto iter : ifaces) {
        printf("    -> Name: '%s'   IP address: %s\n",
            iter.name().c_str(),
            iter.ipv4_address().to_string().c_str());
    }
    exit(0);
}

auto getLocalIps() -> std::vector<Tins::IPv4Address>
{
    std::vector<Tins::IPv4Address> res;
    const std::vector<Tins::NetworkInterface> ifaces = Tins::NetworkInterface::all();
    for (auto iter : ifaces) {
        if (iter.ipv4_address().is_unicast()) {
            res.push_back(iter.ipv4_address());
        }
    }
    return res;
}

auto getPcapReader(const std::string& pcapFileName, std::string filter) -> Tins::FileSniffer*
{
    Tins::FileSniffer* reader = new Tins::FileSniffer(pcapFileName, filter);
    return reader;
}

auto analyzePcapFile(FlowstatsConfiguration& conf, Collector* collector) -> int
{
    std::vector<Collector*> collectors;
    collectors.push_back(collector);
    return analyzePcapFile(conf, collectors);
}

/**
 * analysis pcap file
 */
auto analyzePcapFile(FlowstatsConfiguration& conf,
    std::vector<Collector*> collectors) -> int
{
    Tins::FileSniffer* reader = getPcapReader(conf.pcapFileName, conf.bpfFilter);
    if (reader == nullptr) {
        return 1;
    }

    timeval start = { 0, 0 };
    timeval end = { 0, 0 };
    for (auto packet : *reader) {
        if (packet.timestamp().seconds() == 0) {
            break;
        }

        spdlog::debug("parsedPacket: {}", packet.pdu()->pdu_type());
        auto pktTv = packetToTimeval(packet);
        if (start.tv_sec == 0) {
            start = pktTv;
        }
        for (auto* collector : collectors) {
            collector->processPacket(packet);
        }
    }

    for (auto& collector : collectors) {
        collector->advanceTick(maxTimeval);
        int delta = getTimevalDeltaS(start, end);
        CollectorOutput o = collector->outputStatus(delta);
        o.print();
    }
    delete reader;
    return 0;
}

auto getLiveDevice(const FlowstatsConfiguration& conf) -> Tins::Sniffer*
{
    Tins::SnifferConfiguration snifferConf;
    snifferConf.set_promisc_mode(1);
    snifferConf.set_filter(conf.bpfFilter);
    Tins::Sniffer* dev = new Tins::Sniffer(conf.interfaceNameOrIP, snifferConf);
    return dev;
}

/**
 * analysis live traffic
 */
auto analyzeLiveTraffic(Tins::Sniffer* dev, FlowstatsConfiguration& conf,
    std::vector<Collector*> collectors,
    std::atomic_bool& shouldStop, Screen& screen) -> int
{
    long startTs = time(nullptr);
    spdlog::info("Start live traffic capture with filter {}", conf.bpfFilter);
    int lastUpdate = 0;
    for (auto packet : *dev) {
        if (shouldStop.load()) {
            break;
        }
        for (auto& collector : collectors) {
            try {
                collector->processPacket(packet);
            } catch (const Tins::malformed_packet) {
                // Good to ignore
            } catch (const Tins::pdu_not_found) {
                // Good to ignore
            }
        }

        int pktSeconds = packet.timestamp().seconds();
        if (lastUpdate < pktSeconds) {
            lastUpdate = pktSeconds;
            screen.updateDisplay(time(nullptr) - startTs, true);
            for (auto& collector : collectors) {
                collector->sendMetrics();
                collector->resetMetrics();
            }
        }
    }

    spdlog::info("Stop capture");
    dev->stop_sniff();
    spdlog::info("Stopping screen");
    screen.StopDisplay();

    fmt::print("\n");
    long endTs = time(nullptr);
    for (auto& collector : collectors) {
        collector->advanceTick(maxTimeval);
        collector->sendMetrics();
        collector->resetMetrics();

        int delta = endTs - startTs;
        CollectorOutput o = collector->outputStatus(delta);
        fmt::print("{} {}s\n", o.name, delta);
        for (int i = 0; i < o.keys.size(); ++i) {
            fmt::print("{} {}\n", o.keys[i], o.values[i]);
        }
        fmt::print("\n");
    }

    return 0;
}
} // namespace flowstats
