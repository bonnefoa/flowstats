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
    for (auto const& iter : ifaces) {
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

auto PktSource::getCaptureStatus() -> std::array<std::string, 2>
{
    if (liveDevice == nullptr) {
        return {};
    }
    pcap_stat pcapStat;
    pcap_stats(liveDevice->get_pcap_handle(), &pcapStat);
    auto pktRate = pcapStat.ps_recv;
    auto dropRate = pcapStat.ps_drop;
    auto ifDropRate = pcapStat.ps_ifdrop;
    if (lastPcapStat.ps_recv > 0) {
        pktRate = pcapStat.ps_recv - lastPcapStat.ps_recv;
        dropRate = pcapStat.ps_drop - lastPcapStat.ps_drop;
        ifDropRate = pcapStat.ps_ifdrop - lastPcapStat.ps_ifdrop;
    }
    lastPcapStat = pcapStat;
    auto stats = fmt::format("Packets recv: {:>8}, drop: {:>6}, ifDrop: {:>6}\n", pcapStat.ps_recv, pcapStat.ps_drop, pcapStat.ps_ifdrop);
    auto rate = fmt::format("Packets recv:   {:>6}/s, drop: {:>4}/s, ifDrop: {:>4}/s\n", pktRate, dropRate, ifDropRate);
    return { stats, rate };
}

auto PktSource::getLiveDevice() -> Tins::Sniffer*
{
    Tins::SnifferConfiguration snifferConf;
    snifferConf.set_promisc_mode(true);
    snifferConf.set_immediate_mode(true);
    snifferConf.set_filter(conf.getBpfFilter());
    try {
        auto* dev = new Tins::Sniffer(conf.getInterfaceName(), snifferConf);
        return dev;
    } catch (Tins::pcap_error const& err) {
        spdlog::error("Could not open device {}: \"{}\"",
            conf.getInterfaceName(),
            err.what());
    }
    return nullptr;
}

auto PktSource::updateScreen(int currentTime) -> void
{
    if (lastUpdate < currentTime) {
        lastUpdate = currentTime;
        auto captureStatus = getCaptureStatus();
        screen->updateDisplay(currentTime, true, captureStatus);
        for (auto* collector : collectors) {
            collector->sendMetrics();
            collector->resetMetrics();
        }
    }
}

auto PktSource::processPacketSource(Tins::Packet const& packet) -> void
{
    auto const* pdu = packet.pdu();
    auto const* ip = pdu->find_pdu<Tins::IP>();
    if (ip == nullptr) {
        return;
    }
    auto const* tcp = ip->find_pdu<Tins::TCP>();
    Tins::UDP const* udp = nullptr;
    if (tcp == nullptr) {
        udp = ip->find_pdu<Tins::UDP>();
        if (udp == nullptr) {
            return;
        }
    }

    auto flowId = tcp ? FlowId(*ip, *tcp) : FlowId(*ip, *udp);
    timeval pktTs = packetToTimeval(packet);
    for (auto* collector : collectors) {
        collector->advanceTick(pktTs);
        try {
            collector->processPacket(packet, flowId, *ip, tcp, udp);
        } catch (const Tins::malformed_packet&) {
            spdlog::info("Malformed packet: {}", packet);
        }
    }
    lastTs = packet.timestamp().seconds();
    updateScreen(lastTs);
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

    for (auto packet : *reader) {
        if (packet.timestamp().seconds() == 0) {
            break;
        }
        processPacketSource(packet);
    }
    delete reader;

    for (auto* collector : collectors) {
        collector->resetMetrics();
    }
    if (screen->getDisplayConf()->noCurses) {
        return 0;
    }

    while (!shouldStop->load()) {
        sleep(1);
    }

    return 0;
}

/**
 * analysis live traffic
 */
auto PktSource::analyzeLiveTraffic() -> int
{
    spdlog::info("Start live traffic capture with filter {}",
        conf.getBpfFilter());
    liveDevice = getLiveDevice();
    if (liveDevice == nullptr) {
        return -1;
    }
    for (const auto& packet : *liveDevice) {
        if (shouldStop->load()) {
            break;
        }
        processPacketSource(packet);
    }

    spdlog::info("Stop capture");
    liveDevice->stop_sniff();
    spdlog::info("Stopping screen");
    screen->StopDisplay();
    return 0;
}
} // namespace flowstats
