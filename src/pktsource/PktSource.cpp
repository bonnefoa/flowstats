#include "PktSource.hpp"
#include "Utils.hpp"
#include <cstdint>
#include <sys/stat.h>
#include <tins/ipv6.h>
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

auto PktSource::getCaptureStatus() -> std::optional<CaptureStat>
{
    if (liveDevice == nullptr) {
        return {};
    }
    pcap_stat pcapStat = {};
    pcap_stats(liveDevice->get_pcap_handle(), &pcapStat);
    auto captureStat = CaptureStat(pcapStat);
    return captureStat;
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

auto PktSource::updateScreen(timeval currentTime) -> void
{
    if (lastUpdate.tv_sec < currentTime.tv_sec) {
        lastUpdate = currentTime;
        auto captureStatus = getCaptureStatus();
        screen->updateDisplay(currentTime, true, captureStatus);
    }
}

auto PktSource::processPacketSource(Tins::Packet const& packet) -> void
{
    auto const* pdu = packet.pdu();
    auto const* ip = pdu->find_pdu<Tins::IP>();
    Tins::IPv6 const* ipv6 = nullptr;
    Tins::PDU const* ipPdu;
    if (ip == nullptr) {
        ipv6 = pdu->find_pdu<Tins::IPv6>();
        if (ipv6 == nullptr) {
            return;
        }
        ipPdu = ipv6;
    } else {
        ipPdu = ip;
    }
    auto const* tcp = ipPdu->find_pdu<Tins::TCP>();
    Tins::UDP const* udp = nullptr;
    if (tcp == nullptr) {
        udp = ipPdu->find_pdu<Tins::UDP>();
        if (udp == nullptr) {
            return;
        }
    }

    auto flowId = FlowId(ip, ipv6, tcp, udp);
    timeval pktTs = packetToTimeval(packet);
    for (auto* collector : collectors) {
        collector->advanceTick(pktTs);
        try {
            collector->processPacket(packet, flowId, ip, ipv6, tcp, udp);
        } catch (const Tins::malformed_packet&) {
            SPDLOG_INFO("Malformed packet: {}", packet);
        }
    }
    if (screen) {
        auto ts = packet.timestamp();
        updateScreen({ ts.seconds(), ts.microseconds() / 1000 });
    }
}

/**
 * analysis pcap file
 */
auto PktSource::analyzePcapFile() -> int
{
    struct stat buffer = {};
    if (stat(conf.getPcapFileName().c_str(), &buffer) != 0) {
        SPDLOG_ERROR("File {} doesn't exist", conf.getPcapFileName());
        return -1;
    }
    auto reader = Tins::FileSniffer(conf.getPcapFileName(), conf.getBpfFilter());

    int lastSecond = 0;
    for (auto const& packet : reader) {
        auto pktSecond = packet.timestamp().seconds();
        if (packet.timestamp().seconds() == 0) {
            break;
        }
        if (lastSecond != pktSecond && shouldStop->load()) {
            break;
        }
        lastSecond = pktSecond;
        processPacketSource(packet);
    }

    for (auto* collector : collectors) {
        collector->resetMetrics();
    }
    if (screen->getNoCurses()) {
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
    SPDLOG_INFO("Start live traffic capture with filter {}",
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

    SPDLOG_INFO("Stop capture");
    liveDevice->stop_sniff();
    return 0;
}
} // namespace flowstats
