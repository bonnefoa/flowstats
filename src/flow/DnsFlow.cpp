#include "DnsFlow.hpp"
#include <spdlog/spdlog.h>

namespace flowstats {

auto dnsTypeToString(Tins::DNS::QueryType dnsType) -> std::string
{
#define ENUM_TEXT(p)                \
    case (Tins::DNS::QueryType::p): \
        return #p;
    switch (dnsType) {
        ENUM_TEXT(A);
        ENUM_TEXT(NS);
        ENUM_TEXT(MD);
        ENUM_TEXT(MF);
        ENUM_TEXT(CNAME);
        ENUM_TEXT(SOA);
        ENUM_TEXT(MB);
        ENUM_TEXT(MG);
        ENUM_TEXT(MR);
        ENUM_TEXT(NULL_R);
        ENUM_TEXT(WKS);
        ENUM_TEXT(PTR);
        ENUM_TEXT(HINFO);
        ENUM_TEXT(MINFO);
        ENUM_TEXT(MX);
        ENUM_TEXT(TXT);
        ENUM_TEXT(RP);
        ENUM_TEXT(AFSDB);
        ENUM_TEXT(X25);
        ENUM_TEXT(ISDN);
        ENUM_TEXT(RT);
        ENUM_TEXT(NSAP);
        ENUM_TEXT(NSAP_PTR);
        ENUM_TEXT(SIG);
        ENUM_TEXT(KEY);
        ENUM_TEXT(PX);
        ENUM_TEXT(GPOS);
        ENUM_TEXT(AAAA);
        ENUM_TEXT(LOC);
        ENUM_TEXT(NXT);
        ENUM_TEXT(EID);
        ENUM_TEXT(NIMLOC);
        ENUM_TEXT(SRV);
        ENUM_TEXT(ATMA);
        ENUM_TEXT(NAPTR);
        ENUM_TEXT(KX);
        ENUM_TEXT(CERT);
        ENUM_TEXT(A6);
        ENUM_TEXT(DNAM);
        ENUM_TEXT(SINK);
        ENUM_TEXT(OPT);
        ENUM_TEXT(APL);
        ENUM_TEXT(DS);
        ENUM_TEXT(SSHFP);
        ENUM_TEXT(IPSECKEY);
        ENUM_TEXT(RRSIG);
        ENUM_TEXT(NSEC);
        ENUM_TEXT(DNSKEY);
        ENUM_TEXT(DHCID);
        ENUM_TEXT(NSEC3);
        ENUM_TEXT(NSEC3PARAM);
    default:
        return "Unknown";
    }
}
} // namespace flowstats
