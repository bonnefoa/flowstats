#pragma once

#include "Flow.hpp"
#include <dns.h>

namespace flowstats {

class DnsFlow : public Flow {

public:
    std::string fqdn;
    bool hasResponse;
    bool isTcp;
    bool truncated;
    enum Tins::DNS::QueryType type;
    uint16_t numberRecords;
    uint8_t responseCode;

    timeval m_StartTimestamp;
    timeval m_EndTimestamp;

    DnsFlow()
    {
        fqdn = "";
        hasResponse = false;
        isTcp = false;
        truncated = false;
        type = Tins::DNS::A;
        numberRecords = 0;
        responseCode = 0;
        m_StartTimestamp = { 0, 0 };
        m_EndTimestamp = { 0, 0 };
    }

    DnsFlow(Tins::PDU* pdu)
        : Flow(pdu)
    {
        DnsFlow();
    }
};

std::string dnsTypeToString(Tins::DNS::QueryType queryType);
}
