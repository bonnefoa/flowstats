#pragma once

#include "Configuration.hpp"
#include "IPAddress.hpp"
#include <cstdint>
#include <ctime> // for time_t, timeval
#include <iosfwd> // for size_t
#include <limits>
#include <map>
#include <optional> // for optional
#include <set>
#include <string>
#include <tins/ip.h>
#include <tins/ip_address.h>
#include <tins/packet.h>
#include <tins/tcp.h>
#include <tins/udp.h>
#include <vector>

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

namespace flowstats {

auto caseInsensitiveComp(char c1, char c2) -> bool;
auto getTimevalDeltaMs(timeval start, timeval end) -> uint32_t;
auto getTimevalDeltaS(timeval start, timeval end) -> uint32_t;
auto timevalInMs(timeval tv) -> uint32_t;

enum Direction {
    FROM_CLIENT,
    FROM_SERVER,
    MERGED,
};

auto directionToString(enum Direction direction) -> std::string;
auto directionToString(uint8_t direction) -> std::string;
auto clearScreen() -> void;

time_t const maxTime = std::numeric_limits<time_t>::max();
timeval const maxTimeval { maxTime, 0 };

auto split(std::string const& s, char delimiter) -> std::vector<std::string>;
auto splitSet(std::string const& s, char delimiter) -> std::set<std::string>;
auto resolveDns(std::string const& domain) -> std::vector<std::string>;
auto stringsToInts(std::vector<std::string> const& strInts) -> std::set<int>;

template <typename T>
auto prettyFormatBytes(T bytes) -> std::string;
auto prettyFormatBytesAverage(int bytes, int duration) -> std::string;
template <typename T>
auto prettyFormatNumber(T num) -> std::string;

auto prettyFormatNumberAverage(int num, int duration) -> std::string;
auto prettyFormatMs(int ms) -> std::string;

auto getIpToFqdn(std::vector<std::string> const& initialDomains) -> std::map<uint32_t, std::string>;
auto getDomainToServerPort(std::vector<std::string> const& initialServerPorts) -> std::map<std::string, uint16_t>;

auto packetToTimeval(Tins::Packet const& packet) -> timeval;
auto ipv4ToString(uint32_t ipv4) -> std::string;
auto getTopMapPair(std::map<IPAddress, uint64_t> const& src, int num) -> std::vector<std::pair<IPAddress, uint64_t>>;
auto setOrIncreaseMapValue(std::map<IPAddress, uint64_t>* map, IPAddress key, uint64_t val) -> void;
auto getWithWarparound(int currentValue, int max, int delta) -> int;

} // namespace flowstats
