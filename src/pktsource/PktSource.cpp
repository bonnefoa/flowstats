#include "PktSource.hpp"
#include "Utils.hpp"
#include <PcapFilter.h>
#include <PlatformSpecificUtils.h>
#include <SSLLayer.h>
#include <spdlog/spdlog.h>

#include <utility>

namespace flowstats {

using namespace pcpp;

/**
 * Go over all interfaces and output their names
 */
void listInterfaces()
{
    const std::vector<PcapLiveDevice*>& devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

    printf("\nNetwork interfaces:\n");
    for (auto iter : devList) {
        printf("    -> Name: '%s'   IP address: %s\n", iter->getName(),
            iter->getIPv4Address().toString().c_str());
    }
    exit(0);
}

auto getLocalIps() -> std::vector<pcpp::IPv4Address>
{
    std::vector<pcpp::IPv4Address> res;
    const std::vector<PcapLiveDevice*>& devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    for (auto iter : devList) {
        if (iter->getIPv4Address() != pcpp::IPv4Address::Zero) {
            res.push_back(iter->getIPv4Address());
        }
    }
    return res;
}

auto getPcapReader(const std::string& pcapFileName, std::string filter) -> pcpp::IFileReaderDevice*
{
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcapFileName.c_str());

    if (!reader->open()) {
        spdlog::error("Could not open input pcap file");
        return nullptr;
    }
    reader->setFilter(std::move(filter));
    return reader;
}

auto analyzePcapFile(FlowstatsConfiguration& conf, Collector* collector) -> int
{
    std::vector<Collector*> collectors;
    collectors.push_back(collector);
    return analyzePcapFile(conf, collectors);
}

void detectTls(Packet& packet, Layer* lastLayer)
{
    size_t dataLen = lastLayer->getDataLen();
    if (dataLen == 0) {
        return;
}
    uint8_t* data = lastLayer->getData();
    if (dataLen < 5) {
        return;
    }
    // Tls handshake
    if (data[0] != 0x16) {
        return;
    }
    // Tls version
    if (data[1] != 0x3 && (data[2] > 0x3)) {
        return;
    }
    uint16_t size = 0;
    size += (data[3] << 8) + data[4];
    if (dataLen != size + 5) {
        return;
    }
    spdlog::debug("Detected tls handshake");

    if (packet.removeLastLayer() == false) {
        spdlog::debug("Last layer not removed");
    }
    Layer* sslLayer = pcpp::SSLLayer::createSSLMessage(data, dataLen,
        lastLayer->getPrevLayer(), &packet);

    if (packet.addLayer(sslLayer) == false) {
        spdlog::debug("ssl layer not appended");
    }
}

/**
 * analysis pcap file
 */
auto analyzePcapFile(FlowstatsConfiguration& conf,
    std::vector<Collector*> collectors) -> int
{
    IFileReaderDevice* reader = getPcapReader(conf.pcapFileName, conf.bpfFilter);
    if (reader == nullptr) {
        return 1;
    }
    RawPacket rawPacket;
    timespec start = { 0, 0 };
    timespec end = { 0, 0 };
    while (reader->getNextPacket(rawPacket)) {
        Packet parsedPacket(&rawPacket);
        Layer* lastLayer = parsedPacket.getLastLayer();
        if (lastLayer->getProtocol() == pcpp::TCP) {
            detectTls(parsedPacket, lastLayer);
        }
        spdlog::debug("parsedPacket: {}", parsedPacket.toString());
        end = parsedPacket.getRawPacketReadOnly()->getPacketTimeStamp();
        if (start.tv_sec == 0) {
            start = parsedPacket.getRawPacketReadOnly()->getPacketTimeStamp();
        }
        for (auto* collector : collectors) {
            collector->processPacket(&parsedPacket);
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

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the
 * endless while loop
 */
/**
 * packet capture callback - called whenever a packet arrives
 */
static void packetArrive(RawPacket* packet,
    __attribute__((unused)) PcapLiveDevice* dev,
    void* cookie)
{
    Packet parsedPacket(packet);

    auto* collectors = static_cast<std::vector<Collector*>*>(cookie);
    for (auto collector : *collectors) {
        collector->processPacket(&parsedPacket);
    }
}

/**
 * analysis live traffic
 */
auto analyzeLiveTraffic(PcapLiveDevice* dev, FlowstatsConfiguration& conf,
    DisplayConfiguration&  /*displayConf*/, std::vector<Collector*> collectors,
    std::atomic_bool& shouldStop, Screen& screen) -> int
{
    pcpp::PcapLiveDevice::DeviceConfiguration deviceConf(PcapLiveDevice::Promiscuous, 1);
    if (!dev->open(deviceConf)) {
        spdlog::error("Could not open the device");
        return 1;
    }

    dev->setFilter(conf.bpfFilter);
    dev->startCapture(packetArrive, &collectors);

    long startTs = time(nullptr);
    spdlog::info("Start live traffic capture with filter {}", conf.bpfFilter);
    while (!shouldStop.load()) {
        screen.updateDisplay(time(nullptr) - startTs, true);
        for (auto& collector : collectors) {
            collector->sendMetrics();
            collector->resetMetrics();
        }
        PCAP_SLEEP(1);
    }
    spdlog::info("Stop capture");
    dev->stopCapture();
    spdlog::info("Close device");
    dev->close();
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

auto getLiveDevice(const std::string& interfaceNameOrIP) -> PcapLiveDevice*
{
    PcapLiveDevice* dev = nullptr;
    IPv4Address interfaceIP(interfaceNameOrIP);
    if (interfaceIP.isValid()) {
        dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
        if (dev == nullptr) {
            spdlog::error("Couldn't find interface by provided IP");
}
    } else {
        dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(
            interfaceNameOrIP);
        if (dev == nullptr) {
            spdlog::error("Couldn't find interface by provided name");
}
    }
    return dev;
}
}  // namespace flowstats
