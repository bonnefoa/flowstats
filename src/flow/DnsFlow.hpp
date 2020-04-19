#pragma once

#include "Flow.hpp"
#include <DnsLayer.h>

namespace flowstats {

class DnsFlow : public Flow {

public:
    std::string fqdn;
    bool hasResponse;
    bool isTcp;
    bool truncated;
    enum pcpp::DnsType type;
    uint16_t numberRecords;
    uint8_t responseCode;

    timespec m_StartTimestamp;
    timespec m_EndTimestamp;

    DnsFlow()
    {
        fqdn = "";
        hasResponse = false;
        isTcp = false;
        truncated = false;
        type = pcpp::DNS_TYPE_ALL;
        numberRecords = 0;
        responseCode = 0;
        m_StartTimestamp = { 0, 0 };
        m_EndTimestamp = { 0, 0 };
    }

    DnsFlow(pcpp::Packet* packet)
        : Flow(packet)
    {
        DnsFlow();
    }
};

std::string dnsTypeToString(pcpp::DnsType dnsType);
}
