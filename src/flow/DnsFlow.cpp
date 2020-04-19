#include "DnsFlow.hpp"
#include <spdlog/spdlog.h>

namespace flowstats {

auto dnsTypeToString(pcpp::DnsType dnsType) -> std::string
{
    switch (dnsType) {
    case pcpp::DNS_TYPE_A:
        return "A";
    case pcpp::DNS_TYPE_NS:
        return "NS";
    case pcpp::DNS_TYPE_MD:
        return "MD";
    case pcpp::DNS_TYPE_MF:
        return "MF";
    case pcpp::DNS_TYPE_CNAME:
        return "CNAME";
    case pcpp::DNS_TYPE_SOA:
        return "SOA";
    case pcpp::DNS_TYPE_MB:
        return "MB";
    case pcpp::DNS_TYPE_MG:
        return "MG";
    case pcpp::DNS_TYPE_MR:
        return "MR";
    case pcpp::DNS_TYPE_NULL_R:
        return "NULL_R";
    case pcpp::DNS_TYPE_WKS:
        return "WKS";
    case pcpp::DNS_TYPE_PTR:
        return "PTR";
    case pcpp::DNS_TYPE_HINFO:
        return "HINFO";
    case pcpp::DNS_TYPE_MINFO:
        return "MINFO";
    case pcpp::DNS_TYPE_MX:
        return "MX";
    case pcpp::DNS_TYPE_TXT:
        return "TXT";
    case pcpp::DNS_TYPE_RP:
        return "RP";
    case pcpp::DNS_TYPE_AFSDB:
        return "AFSDB";
    case pcpp::DNS_TYPE_X25:
        return "X25";
    case pcpp::DNS_TYPE_ISDN:
        return "ISDN";
    case pcpp::DNS_TYPE_RT:
        return "RT";
    case pcpp::DNS_TYPE_NSAP:
        return "NSAP";
    case pcpp::DNS_TYPE_NSAP_PTR:
        return "NSAP_PTR";
    case pcpp::DNS_TYPE_SIG:
        return "SIG";
    case pcpp::DNS_TYPE_KEY:
        return "KEY";
    case pcpp::DNS_TYPE_PX:
        return "PX";
    case pcpp::DNS_TYPE_GPOS:
        return "GPOS";
    case pcpp::DNS_TYPE_AAAA:
        return "AAAA";
    case pcpp::DNS_TYPE_LOC:
        return "LOC";
    case pcpp::DNS_TYPE_NXT:
        return "NXT";
    case pcpp::DNS_TYPE_EID:
        return "EID";
    case pcpp::DNS_TYPE_NIMLOC:
        return "NIMLOC";
    case pcpp::DNS_TYPE_SRV:
        return "SRV";
    case pcpp::DNS_TYPE_ATMA:
        return "ATMA";
    case pcpp::DNS_TYPE_NAPTR:
        return "NAPTR";
    case pcpp::DNS_TYPE_KX:
        return "KX";
    case pcpp::DNS_TYPE_CERT:
        return "CERT";
    case pcpp::DNS_TYPE_A6:
        return "A6";
    case pcpp::DNS_TYPE_DNAM:
        return "DNAM";
    case pcpp::DNS_TYPE_SINK:
        return "SINK";
    case pcpp::DNS_TYPE_OPT:
        return "OPT";
    case pcpp::DNS_TYPE_APL:
        return "APL";
    case pcpp::DNS_TYPE_DS:
        return "DS";
    case pcpp::DNS_TYPE_SSHFP:
        return "SSHFP";
    case pcpp::DNS_TYPE_IPSECKEY:
        return "IPSECKEY";
    case pcpp::DNS_TYPE_RRSIG:
        return "RRSIG";
    case pcpp::DNS_TYPE_NSEC:
        return "NSEC";
    case pcpp::DNS_TYPE_DNSKEY:
        return "DNSKEY";
    case pcpp::DNS_TYPE_DHCID:
        return "DHCID";
    case pcpp::DNS_TYPE_NSEC3:
        return "NSEC3";
    case pcpp::DNS_TYPE_NSEC3PARAM:
        return "NSEC3PARAM";
    case pcpp::DNS_TYPE_ALL:
        return "ALL";
    default:
        return "Unknown";
    }
}
}  // namespace flowstats
