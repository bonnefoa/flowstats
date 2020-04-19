#pragma once

#include "Collector.hpp"
#include "Configuration.hpp"
#include "Screen.hpp"
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <stdlib.h>

namespace flowstats {

void listInterfaces(void);
std::vector<pcpp::IPv4Address> getLocalIps(void);
int analyzeLiveTraffic(pcpp::PcapLiveDevice* dev, FlowstatsConfiguration& conf,
    DisplayConfiguration& displayConf, std::vector<Collector*> collectors,
    std::atomic_bool& shouldStop, Screen& screen);
int analyzePcapFile(FlowstatsConfiguration& conf, Collector* collector);
int analyzePcapFile(FlowstatsConfiguration& conf, std::vector<Collector*> collectors);
pcpp::PcapLiveDevice* getLiveDevice(const std::string& interfaceNameOrIP);
pcpp::IFileReaderDevice* getPcapReader(const std::string& pcapFileName, std::string filter);

}
