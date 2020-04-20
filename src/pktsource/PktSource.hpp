#pragma once

#include "Collector.hpp"
#include "Configuration.hpp"
#include "Screen.hpp"
#include <ip_address.h>
#include <sniffer.h>
#include <stdlib.h>

namespace flowstats {

void listInterfaces(void);
std::vector<Tins::IPv4Address> getLocalIps(void);
int analyzeLiveTraffic(Tins::Sniffer* dev, FlowstatsConfiguration& conf,
    std::vector<Collector*> collectors,
    std::atomic_bool& shouldStop, Screen& screen);
int analyzePcapFile(FlowstatsConfiguration& conf, Collector* collector);
int analyzePcapFile(FlowstatsConfiguration& conf, std::vector<Collector*> collectors);
Tins::Sniffer* getLiveDevice(const std::string& interfaceNameOrIP, FlowstatsConfiguration& conf);
Tins::FileSniffer* getPcapReader(const std::string& pcapFileName, std::string filter);

}
