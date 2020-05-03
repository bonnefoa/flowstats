#pragma once

#include "Flow.hpp"
#include <tins/dns.h>

namespace flowstats {

class DnsFlow : public Flow {

public:
    std::string fqdn = "";
    bool hasResponse = false;
    bool isTcp = false;
    bool truncated = false;
    enum Tins::DNS::QueryType type = Tins::DNS::A;
    uint16_t numberRecords = 0;
    uint8_t responseCode = 0;

    timeval startTv = {};
    timeval endTv = {};

    DnsFlow() {}
    DnsFlow(const Tins::Packet& packet)
        : Flow(packet)
    {
        DnsFlow();
    }
};

auto dnsTypeToString(Tins::DNS::QueryType queryType) -> std::string;
}
