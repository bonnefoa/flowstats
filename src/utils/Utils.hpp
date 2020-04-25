#pragma once

#include "Configuration.hpp"
#include <cstdint>
#include <ctime> // for time_t, timeval
#include <iosfwd> // for size_t
#include <ip.h>
#include <ip_address.h>
#include <limits>
#include <map>
#include <optional> // for optional
#include <packet.h>
#include <set>
#include <string>
#include <tcp.h>
#include <udp.h>
#include <vector>

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

namespace flowstats {

auto getTimevalDeltaMs(timeval start, timeval end) -> uint32_t;
auto getTimevalDeltaS(timeval start, timeval end) -> uint32_t;
auto timevalInMs(timeval tv) -> uint32_t;

enum Direction {
    FROM_CLIENT,
    FROM_SERVER,
};

auto directionToString(enum Direction direction) -> std::string;
auto directionToString(uint8_t direction) -> std::string;
auto clearScreen() -> void;

time_t const maxTime = std::numeric_limits<time_t>::max();
timeval const maxTimeval { maxTime, 0 };

auto split(const std::string& s, char delimiter) -> std::vector<std::string>;
auto splitSet(const std::string& s, char delimiter) -> std::set<std::string>;
auto resolveDns(const std::string& domain) -> std::vector<std::string>;
auto stringsToInts(const std::vector<std::string>& strInts) -> std::set<int>;

template <std::size_t N>
auto fmtVector(const std::string& format, const std::vector<std::string>& v) -> std::string;
auto prettyFormatBytes(int bytes) -> std::string;
auto prettyFormatNumber(int num) -> std::string;
auto prettyFormatMs(int ms) -> std::string;

auto getIpToFqdn(const std::vector<std::string>& initialDomains) -> std::map<uint32_t, std::string>;
auto getDomainToServerPort(const std::vector<std::string>& initialServerPorts) -> std::map<std::string, uint16_t>;

auto getFlowFqdn(FlowstatsConfiguration& conf, uint32_t srvIp) -> std::optional<std::string>;

auto packetToTimeval(const Tins::Packet& packet) -> timeval;
} // namespace flowstats
