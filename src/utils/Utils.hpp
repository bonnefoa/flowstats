#pragma once

#include "Configuration.hpp"
#include <cstdint>
#include <iosfwd> // for size_t
#include <ip.h>
#include <ip_address.h>
#include <limits>
#include <map>
#include <optional> // for optional
#include <set>
#include <string>
#include <tcp.h>
#include <time.h> // for time_t, timeval
#include <udp.h>
#include <vector>

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

namespace flowstats {

uint32_t getTimevalDeltaMs(timeval start, timeval end);
uint32_t getTimevalDeltaS(timeval start, timeval end);

uint64_t timevalInMs(timeval tv);

enum Direction {
    FROM_CLIENT,
    FROM_SERVER,
};

std::string directionToString(enum Direction direction);
std::string directionToString(uint8_t direction);
void clearScreen();

time_t const maxTime = std::numeric_limits<time_t>::max();
timeval const maxTimeval { maxTime, 0 };

std::vector<std::string> split(const std::string& s, char delimiter);
std::set<std::string> splitSet(const std::string& s, char delimiter);
std::vector<std::string> resolveDns(const std::string& domain);
std::set<int> stringsToInts(std::vector<std::string>& strInts);

template <std::size_t N>
std::string fmtVector(const std::string& format, const std::vector<std::string>& v);
std::string prettyFormatBytes(int bytes);
std::string prettyFormatNumber(int num);
std::string prettyFormatMs(int ms);

std::map<uint32_t, std::string> getIpToFqdn();
std::map<uint32_t, std::string> getIpToFqdn(std::vector<std::string>& initialDomains);
std::map<std::string, uint16_t> getDomainToServerPort(std::vector<std::string>& initialServerPorts);

uint32_t hash5Tuple(Tins::IP* ipv4Layer, uint16_t portSrc, uint16_t portDst);

std::optional<std::string> getFlowFqdn(FlowstatsConfiguration& conf, uint32_t srvIp);
}
