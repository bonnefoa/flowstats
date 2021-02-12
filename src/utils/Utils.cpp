#include "Utils.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <netdb.h>
#include <tins/pdu.h>

namespace flowstats {

auto caseInsensitiveComp(char c1, char c2) -> bool
{
    return std::tolower(c1) < std::tolower(c2);
}

auto getTimevalDeltaMs(timeval start, timeval end) -> uint32_t
{
    return (end.tv_sec * 1000 + end.tv_usec / 1000) - (start.tv_sec * 1000 + start.tv_usec / 1000);
}

auto timevalInMs(timeval tv) -> uint32_t
{
    uint32_t ms = 1000 * tv.tv_sec + tv.tv_usec / 1000;
    return ms;
}

auto getTimevalDeltaS(timeval start, timeval end) -> uint32_t
{
    return end.tv_sec - start.tv_sec;
}

auto directionToString(enum Direction direction) -> std::string
{
    if (direction == FROM_CLIENT) {
        return "C->S";
    }
    return "S->C";
}

auto directionToString(uint8_t direction) -> std::string
{
    if (direction == FROM_CLIENT) {
        return "C->S";
    }
    return "S->C";
}

auto split(std::string const& s, char delimiter) -> std::vector<std::string>
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

auto splitSet(std::string const& s, char delimiter) -> std::set<std::string>
{
    std::set<std::string> res;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        res.insert(token);
    }
    return res;
}

auto stringsToInts(const std::vector<std::string>& strInts) -> std::set<int>
{
    std::set<int> res;
    for (const auto& strInt : strInts) {
        res.insert(atoi(strInt.c_str()));
    }
    return res;
}

auto getDomainToServerPort(const std::vector<std::string>& initialServerPorts) -> std::map<std::string, uint16_t>
{
    std::map<std::string, uint16_t> res;
    for (const auto& serviceToPort : initialServerPorts) {
        std::vector<std::string> pair = split(serviceToPort, ':');
        res[pair[0]] = std::stoi(pair[1]);
    }
    return res;
}

static auto prettyFormatGeneric(int num, std::vector<std::string> const& suffixes) -> std::string
{
    int unit = 0;
    double currentCount = num;
    while (currentCount >= 1000 && unit < suffixes.size()) {
        unit++;
        currentCount /= 1000;
    }
    if (currentCount - floor(currentCount) == 0.0) {
        return fmt::format("{}{}", static_cast<int>(currentCount), suffixes[unit]);
    } else {
        return fmt::format("{:.1f}{}", currentCount, suffixes[unit]);
    }
}

template <typename T>
auto prettyFormatNumber(T num) -> std::string
{
    return prettyFormatGeneric(num, { "", "K", "M", "G", "P" });
}
template auto prettyFormatNumber(uint64_t num) -> std::string;
template auto prettyFormatNumber(uint8_t num) -> std::string;

auto prettyFormatNumberAverage(int total, int duration) -> std::string
{
    if (duration == 0) {
        return "0/s";
    }
    return prettyFormatNumber(total / duration);
}

auto prettyFormatMs(int ms) -> std::string
{
    return prettyFormatGeneric(ms, { "ms", "s" });
}

template <typename T>
auto prettyFormatBytes(T bytes) -> std::string
{
    std::vector<std::string> suffixes = { "B", "KB", "MB", "GB", "TB", "PB", "EB" };
    int unit = 0;
    T currentCount = bytes;
    while (currentCount >= 1024 && unit < suffixes.size()) {
        unit++;
        currentCount /= 1024;
    }
    if (currentCount - floor(currentCount) == 0.0) {
        return fmt::format("{} {}", static_cast<int>(currentCount), suffixes[unit]);
    } else {
        return fmt::format("{:.1f} {}", currentCount, suffixes[unit]);
    }
}
template auto prettyFormatBytes(uint64_t bytes) -> std::string;
template auto prettyFormatBytes(unsigned int bytes) -> std::string;

auto prettyFormatBytesAverage(int bytes, int duration) -> std::string
{
    if (duration == 0) {
        return "0";
    }
    return prettyFormatBytes(bytes / duration);
}

auto packetToTimeval(const Tins::Packet& packet) -> timeval
{
    auto ts = packet.timestamp();
    return { ts.seconds(), ts.microseconds() };
}

auto ipv4ToString(uint32_t ipv4) -> std::string
{
    std::array<uint8_t, 4> ipParts = {
        uint8_t(ipv4 & 0xff),
        uint8_t((ipv4 >> 8) & 0xff),
        uint8_t((ipv4 >> 16) & 0xff),
        uint8_t((ipv4 >> 24) & 0xff),
    };
    return fmt::format("{}.{}.{}.{}", ipParts[0], ipParts[1], ipParts[2], ipParts[3]);
}

auto getTopMapPair(std::map<IPAddress, uint64_t> const& src, int num) -> std::vector<std::pair<IPAddress, uint64_t>>
{
    int size = std::min(num, static_cast<int>(src.size()));
    std::vector<std::pair<IPAddress, uint64_t>> topIps(size);
    std::partial_sort_copy(src.begin(), src.end(),
        topIps.begin(), topIps.end(),
        [](std::pair<IPAddress, uint64_t> const& l,
            std::pair<IPAddress, uint64_t> const& r) {
            return l.second > r.second;
        });
    return topIps;
}

auto getWithWarparound(int currentValue, int max, int delta) -> int
{
    if (delta >= 0) {
        return (currentValue + delta) % max;
    }
    if (currentValue + delta < 0) {
        return (currentValue + max + delta % max);
    }
    return (currentValue + delta);
}

} // namespace flowstats
