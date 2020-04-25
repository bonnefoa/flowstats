#pragma once

#include <DogFood.hpp> // for Configuration
#include <cstdint> // for uint16_t, uint32_t
#include <map> // for map
#include <mutex> // for mutex
#include <optional> // for optional
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

auto sortToString(enum SortType sortType) -> std::string;
auto displayTypeToString(enum DisplayType displayType) -> std::string;

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

    FlowstatsConfiguration() = default;
};

using DisplayPair = std::pair<DisplayType, std::vector<std::string>>;
} // namespace flowstats
