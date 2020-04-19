#pragma once

#include "Configuration.hpp"
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <cstdint>
#include <iosfwd> // for size_t
#include <limits>
#include <map>
#include <optional> // for optional
#include <set>
#include <string>
#include <time.h> // for time_t, timespec
#include <vector>

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

namespace flowstats {

uint32_t getTimevalDeltaMs(timespec start, timespec end);
uint32_t getTimevalDeltaS(timespec start, timespec end);

uint64_t timevalInMs(timespec tv);

enum Direction {
    FROM_CLIENT,
    FROM_SERVER,
};

std::string directionToString(enum Direction direction);
std::string directionToString(uint8_t direction);
void clearScreen();

time_t const maxTime = std::numeric_limits<time_t>::max();
timespec const maxTimeval { maxTime, 0 };

std::vector<std::string> split(const std::string& s, char delimiter);
std::set<std::string> splitSet(const std::string& s, char delimiter);
std::vector<std::string> resolveDns(const std::string& domain);
std::set<int> stringsToInts(std::vector<std::string>& strInts);

template <std::size_t N>
std::string fmtVector(const std::string& format, const std::vector<std::string>& v);
std::string prettyFormatBytes(int bytes);
std::string prettyFormatNumber(int num);
std::string prettyFormatMs(int ms);

std::string protocolToString(pcpp::ProtocolType protocolType);

std::map<uint32_t, std::string> getIpToFqdn();
std::map<uint32_t, std::string> getIpToFqdn(std::vector<std::string>& initialDomains);
std::map<std::string, uint16_t> getDomainToServerPort(std::vector<std::string>& initialServerPorts);

uint32_t hash5Tuple(pcpp::IPv4Layer* ipv4Layer, pcpp::TcpLayer* tcpLayer);
uint32_t hash5Tuple(pcpp::IPv4Layer* ipv4Layer, pcpp::UdpLayer* udpLayer);
uint32_t hash5Tuple(pcpp::IPv4Layer* ipv4Layer, uint16_t portSrc, uint16_t portDst);

std::optional<std::string> getFlowFqdn(FlowstatsConfiguration& conf, uint32_t srvIp);
}
