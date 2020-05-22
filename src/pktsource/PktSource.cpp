#include "PktSource.hpp"
#include "Utils.hpp"
#include <cstdint>
#include <spdlog/spdlog.h>
#include <tins/network_interface.h>
#include <utility>

namespace flowstats {

/**
 * Go over all interfaces and output their names
 */
auto listInterfaces() -> void
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

auto PktSource::getLocalIps() -> std::vector<Tins::IPv4Address>
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

/**
 * analysis pcap file
 */
auto PktSource::analyzePcapFile()
    -> int
{
    auto* reader = new Tins::FileSniffer(conf.getPcapFileName(), conf.getBpfFilter());
    if (reader == nullptr) {
        return 1;
    }
    int lastTs = 0;

    for (auto packet : *reader) {
        if (packet.timestamp().seconds() == 0) {
            break;
        }

        spdlog::debug("parsedPacket: {}", packet.pdu()->pdu_type());
        for (auto* collector : collectors) {
            try {
                collector->processPacket(packet);
            } catch (const Tins::malformed_packet&) {
            } catch (const Tins::pdu_not_found&) {
            }
        }
        lastTs = packet.timestamp().seconds();
        updateScreen(lastTs);
    }
    delete reader;

    for (auto* collector : collectors) {
        collector->resetMetrics();
    }
    if (screen->getDisplayConf().noCurses) {
        return 0;
    }

    while (!shouldStop->load()) {
        sleep(1);
    }

    return 0;
}

auto PktSource::getLiveDevice() -> Tins::Sniffer*
{
    Tins::SnifferConfiguration snifferConf;
    snifferConf.set_promisc_mode(true);
    snifferConf.set_immediate_mode(true);
    snifferConf.set_filter(conf.getBpfFilter());
    auto* dev = new Tins::Sniffer(conf.getInterfaceName(), snifferConf);
    return dev;
}

auto PktSource::updateScreen(int currentTime) -> void
{
    if (lastUpdate < currentTime) {
        lastUpdate = currentTime;
        screen->updateDisplay(currentTime, true);
        for (auto* collector : collectors) {
            collector->sendMetrics();
            collector->resetMetrics();
        }
    }
}

/**
 * analysis live traffic
 */
auto PktSource::analyzeLiveTraffic() -> int
{
    spdlog::info("Start live traffic capture with filter {}",
        conf.getBpfFilter());
    auto* dev = getLiveDevice();
    for (const auto& packet : *dev) {
        if (shouldStop->load()) {
            break;
        }
        for (auto* collector : collectors) {
            try {
                collector->processPacket(packet);
            } catch (const Tins::malformed_packet&) {
            } catch (const Tins::pdu_not_found&) {
            }
        }
        int pktSeconds = packet.timestamp().seconds();
        updateScreen(pktSeconds);
    }

    spdlog::info("Stop capture");
    dev->stop_sniff();
    spdlog::info("Stopping screen");
    screen->StopDisplay();
    return 0;
}
} // namespace flowstats
