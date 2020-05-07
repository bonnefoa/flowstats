#pragma once

#include "Field.hpp"
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
    FlowstatsConfiguration() = default;

    [[nodiscard]] auto getInterfaceName() const -> std::string const& { return iface; };
    [[nodiscard]] auto getPcapFileName() const -> std::string const& { return pcapFileName; };
    [[nodiscard]] auto getBpfFilter() const -> std::string const& { return bpfFilter; };
    [[nodiscard]] auto getDomainToServerPort() const -> std::map<std::string, uint16_t> const& { return domainToServerPort; };
    [[nodiscard]] auto getPerIpAggr() const -> bool const& { return perIpAggr; };
    [[nodiscard]] auto getDisplayUnknownFqdn() const -> bool const& { return displayUnknownFqdn; };
    [[nodiscard]] auto getAgentConf() const -> std::optional<DogFood::Configuration> const& { return agentConf; };
    [[nodiscard]] auto getTimeoutFlow() const -> int const& { return timeoutFlow; };

    auto setBpfFilter(std::string b) { bpfFilter = std::move(b); };
    auto setPcapFileName(std::string p) { pcapFileName = std::move(p); };
    auto setIface(std::string i) { iface = std::move(i); };
    auto setDisplayUnknownFqdn(bool d) { displayUnknownFqdn = d; };
    auto setPerIpAggr(bool p) { perIpAggr = p; };
    auto setAgentConf(std::optional<DogFood::Configuration> a) { agentConf = std::move(a); };
    auto setDomainToServerPort(std::map<std::string, uint16_t> d) { domainToServerPort = std::move(d); };

private:
    std::string iface = "";
    std::string pcapFileName = "";
    std::string bpfFilter = "";

    std::map<std::string, uint16_t> domainToServerPort;
    bool perIpAggr = false;

    bool displayUnknownFqdn = false;
    std::optional<DogFood::Configuration> agentConf;
    int timeoutFlow = 15;
};

using DisplayPair = std::pair<DisplayType, std::vector<Field>>;
} // namespace flowstats
