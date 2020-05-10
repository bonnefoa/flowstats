#pragma once

#include "Flow.hpp"
#include <enum.h>
#include <tins/dns.h>

namespace flowstats {

class DnsFlow : public Flow {

public:
    DnsFlow() = default;
    DnsFlow(const Tins::Packet& packet, Tins::DNS const& dns);

    auto processDnsResponse(Tins::Packet const& packet, Tins::DNS const& dns) -> void;

    [[nodiscard]] auto getFqdn() const { return fqdn; };
    [[nodiscard]] auto getTruncated() const { return truncated; };
    [[nodiscard]] auto getHasResponse() const { return hasResponse; };
    [[nodiscard]] auto getType() const { return type; };
    [[nodiscard]] auto getResponseCode() const { return responseCode; };
    [[nodiscard]] auto getNumberRecords() const { return numberRecords; };
    [[nodiscard]] auto getDeltaTv() const { return getTimevalDeltaMs(startTv, endTv); };
    [[nodiscard]] auto getStartTv() const { return startTv; };

private:
    std::string fqdn = "";
    bool hasResponse = false;
    bool truncated = false;
    enum Tins::DNS::QueryType type = Tins::DNS::A;
    uint16_t numberRecords = 0;
    uint8_t responseCode = 0;

    timeval startTv = {};
    timeval endTv = {};
};

auto dnsTypeToString(Tins::DNS::QueryType queryType) -> std::string;
} // namespace flowstats
