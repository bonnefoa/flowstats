#pragma once

#include <cstdint> // for uint16_t, uint32_t
#include <map> // for map
#include <mutex> // for mutex
#include <optional> // for optional
#include <spdlog/spdlog.h>
#include <string> // for string, allocator

namespace flowstats {

class LogConfiguration {
public:
    LogConfiguration();
    virtual ~LogConfiguration() = default;

    auto setupLog();
    auto setLogDebug() { logger->set_level(spdlog::level::debug); };

private:
    std::shared_ptr<spdlog::logger> logger;
};

class FlowstatsConfiguration : public LogConfiguration {
public:
    FlowstatsConfiguration() = default;

    [[nodiscard]] auto getInterfaceName() const -> std::string const& { return iface; };
    [[nodiscard]] auto getPcapFileName() const -> std::string const& { return pcapFileName; };
    [[nodiscard]] auto getBpfFilter() const -> std::string const& { return bpfFilter; };
    [[nodiscard]] auto getDomainToServerPort() const -> std::map<std::string, uint16_t> const& { return domainToServerPort; };
    [[nodiscard]] auto getPerIpAggr() const -> bool const& { return perIpAggr; };
    [[nodiscard]] auto getDisplayUnknownFqdn() const -> bool const& { return displayUnknownFqdn; };
    [[nodiscard]] auto getTimeoutFlow() const -> int const& { return timeoutFlow; };

    auto setBpfFilter(std::string b) { bpfFilter = std::move(b); };
    auto setPcapFileName(std::string p) { pcapFileName = std::move(p); };
    auto setIface(std::string i) { iface = std::move(i); };
    auto setDisplayUnknownFqdn(bool d) { displayUnknownFqdn = d; };
    auto setPerIpAggr(bool p) { perIpAggr = p; };
    auto setDomainToServerPort(std::map<std::string, uint16_t> d) { domainToServerPort = std::move(d); };

private:
    std::string iface = "";
    std::string pcapFileName = "";
    std::string bpfFilter = "";

    std::map<std::string, uint16_t> domainToServerPort;
    bool perIpAggr = false;

    bool displayUnknownFqdn = false;
    int timeoutFlow = 15;
};

class FlowReplayConfiguration : public LogConfiguration {
public:
    FlowReplayConfiguration() = default;

    auto setBpfFilter(std::string b) { bpfFilter = std::move(b); };
    auto setPcapFileName(std::string p) { pcapFileName = std::move(p); };
    auto setIp(std::string ipStr) { ip = std::move(ipStr); };
    auto setDstPort(uint16_t inPort) { dstPort = inPort; };

    [[nodiscard]] auto getPcapFileName() const -> std::string const& { return pcapFileName; };
    [[nodiscard]] auto getBpfFilter() const -> std::string const& { return bpfFilter; };
    [[nodiscard]] auto getDstPort() const -> uint16_t const& { return dstPort; };
    [[nodiscard]] auto getIp() const -> std::string const& { return ip; };

private:
    uint16_t dstPort = 0;
    std::string pcapFileName = "";
    std::string bpfFilter = "";
    std::string ip = {};
};

} // namespace flowstats
