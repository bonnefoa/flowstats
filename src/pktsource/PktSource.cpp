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
    while (true) {
        Tins::PtrPacket packet = reader->next_packet();
        if (packet.timestamp().seconds() == 0) {
            break;
        }

        spdlog::debug("parsedPacket: {}", packet.pdu()->pdu_type());
        if (start.tv_sec == 0) {
            start = { packet.timestamp().seconds(), packet.timestamp().microseconds() };
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

auto getLiveDevice(const std::string& iface, FlowstatsConfiguration& conf) -> Tins::Sniffer*
{
    Tins::SnifferConfiguration snifferConf;
    snifferConf.set_promisc_mode(1);
    snifferConf.set_filter(conf.bpfFilter);
    Tins::Sniffer* dev = new Tins::Sniffer(iface, snifferConf);
    return dev;
}

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the
 * endless while loop
 */
/**
 * packet capture callback - called whenever a packet arrives
 */
static void packetArrive(Tins::PtrPacket* packet,
    __attribute__((unused)) Tins::Sniffer* dev,
    void* cookie)
{
    //Packet parsedPacket(packet);

    //auto* collectors = static_cast<std::vector<Collector*>*>(cookie);
    //for (auto collector : *collectors) {
    //collector->processPacket(&parsedPacket);
    //}
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
    while (!shouldStop.load()) {
        screen.updateDisplay(time(nullptr) - startTs, true);
        for (auto& collector : collectors) {
            collector->sendMetrics();
            collector->resetMetrics();
        }
        sleep(1);
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
