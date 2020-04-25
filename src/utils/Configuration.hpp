#pragma once

#include <DogFood.hpp> // for Configuration
#include <map> // for map
#include <mutex> // for mutex
#include <optional> // for optional
#include <stdint.h> // for uint16_t, uint32_t
#include <string> // for string, allocator

namespace flowstats {

enum SortType {
    SortFqdn,
    SortPacket,
    SortByte,
    SortRequest,
    SortRequestRate,
    SortSrt,
};

enum DisplayType {
    DisplayRequests,
    DisplayResponses,
    DisplayClients,
    DisplayConnections,
    DisplayFlags,
    DisplayTraffic,
};

std::string sortToString(enum SortType sortType);
std::string displayTypeToString(enum DisplayType displayType);

struct DisplayConfiguration {
    int protocolIndex = 0;
    enum SortType sortType = SortFqdn;
    int maxResults = 15;
    std::string filter;
    bool noCurses = false;
};

struct FlowstatsConfiguration {
    std::string interfaceNameOrIP = "";
    std::string pcapFileName = "";
    std::string bpfFilter = "";

    std::map<std::string, uint16_t> domainToServerPort;
    bool perIpAggr = false;

    bool displayUnknownFqdn = false;
    std::optional<DogFood::Configuration> agentConf;
    int timeoutFlow = 15;

    std::mutex ipToFqdnMutex;
    std::map<uint32_t, std::string> ipToFqdn;
};

using DisplayPair = std::pair<DisplayType, std::vector<std::string>>;
}
