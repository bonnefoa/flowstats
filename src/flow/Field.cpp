#include "Field.hpp"

namespace flowstats {

auto fieldToSortable(Field field) -> bool
{
    switch (field) {
        case Field::DIR:
        case Field::REQ_RATE:
        case Field::FIN_RATE:
        case Field::RST_RATE:
        case Field::SRT_RATE:
        case Field::SYN_RATE:
        case Field::CONN_RATE:
        case Field::PKTS_RATE:
        case Field::ZWIN_RATE:
        case Field::BYTES_RATE:
        case Field::CLOSE_RATE:
        case Field::SYNACK_RATE:
        case Field::TIMEOUTS_RATE:

        case Field::CT_P95:
        case Field::CT_P99:
        case Field::SRT_P95:
        case Field::SRT_P99:
        case Field::DS_P95:
        case Field::DS_P99:

        case Field::RR_A_RATE:
        case Field::RR_AAAA_RATE:
        case Field::RR_CNAME_RATE:
        case Field::RR_PTR_RATE:
        case Field::RR_TXT_RATE:
        case Field::RR_OTHER_RATE:
        case Field::RR_A_AVG:
        case Field::RR_AAAA_AVG:
        case Field::RR_CNAME_AVG:
        case Field::RR_PTR_AVG:
        case Field::RR_TXT_AVG:
        case Field::RR_OTHER_AVG:

        case Field::REQ_AVG:
        case Field::FIN_AVG:
        case Field::RST_AVG:
        case Field::SRT_AVG:
        case Field::SYN_AVG:
        case Field::CONN_AVG:
        case Field::PKTS_AVG:
        case Field::ZWIN_AVG:
        case Field::BYTES_AVG:
        case Field::CLOSE_AVG:
        case Field::SYNACK_AVG:
        case Field::TIMEOUTS_AVG:
        case Field::TOP_CLIENT_IPS_IP:
        case Field::TOP_CLIENT_IPS_PKTS:
        case Field::TOP_CLIENT_IPS_BYTES:
        case Field::TOP_CLIENT_IPS_REQUESTS:
            return false;
        default:
            return true;
    }
}

auto fieldWithRateMode(RateMode rateMode, Field field) -> Field
{
    if (rateMode == +RateMode::AVG) {
        switch (field) {
            case Field::CLOSE_RATE:
                return Field::CLOSE_AVG;
            case Field::CONN_RATE:
                return Field::CONN_AVG;
            case Field::REQ_RATE:
                return Field::REQ_AVG;
            case Field::SRT_RATE:
                return Field::SRT_AVG;
            case Field::PKTS_RATE:
                return Field::PKTS_AVG;
            case Field::BYTES_RATE:
                return Field::BYTES_AVG;
            case Field::SYN_RATE:
                return Field::SYN_AVG;
            case Field::SYNACK_RATE:
                return Field::SYNACK_AVG;
            case Field::ZWIN_RATE:
                return Field::ZWIN_AVG;
            case Field::RST_RATE:
                return Field::RST_AVG;
            case Field::FIN_RATE:
                return Field::FIN_AVG;
            case Field::TIMEOUTS_RATE:
                return Field::TIMEOUTS_AVG;

            case Field::RR_A_RATE:
                return Field::RR_A_AVG;
            case Field::RR_AAAA_RATE:
                return Field::RR_AAAA_AVG;
            case Field::RR_CNAME_RATE:
                return Field::RR_CNAME_AVG;
            case Field::RR_PTR_RATE:
                return Field::RR_PTR_AVG;
            case Field::RR_TXT_RATE:
                return Field::RR_TXT_AVG;
            case Field::RR_OTHER_RATE:
                return Field::RR_OTHER_AVG;
            default:
                break;
        }
    }
    return field;
}

auto fieldWithSubfields(Field field) -> bool
{
    switch (field) {
        case Field::TOP_CLIENT_IPS_IP:
        case Field::TOP_CLIENT_IPS_PKTS:
        case Field::TOP_CLIENT_IPS_BYTES:
        case Field::TOP_CLIENT_IPS_REQUESTS:
            return true;
        default:
            return false;
    }
}

auto fieldToHeader(Field field) -> char const*
{
    switch (field) {
        case Field::ACTIVE_CONNECTIONS: return "ActConn";
        case Field::FAILED_CONNECTIONS: return "FailConn";
        case Field::BYTES: return "Bytes";
        case Field::BYTES_RATE:
        case Field::BYTES_AVG: return "Bytes/s";
        case Field::CLOSE: return "Close";
        case Field::CLOSE_RATE:
        case Field::CLOSE_AVG: return "Close/s";
        case Field::CONN: return "Conn";
        case Field::CONN_RATE:
        case Field::CONN_AVG: return "Conn/s";
        case Field::CT_P95: return "CTp95 (1s)";
        case Field::CT_P99: return "CTp99 (1s)";
        case Field::CT_TOTAL_P95: return "CTp95";
        case Field::CT_TOTAL_P99: return "CTp99";
        case Field::DIR: return "Dir";
        case Field::DOMAIN: return "Domain";
        case Field::FIN: return "FIN";
        case Field::FIN_RATE:
        case Field::FIN_AVG: return "FIN/s";
        case Field::FQDN: return "Fqdn";
        case Field::IP: return "Ip";
        case Field::MTU: return "Mtu";
        case Field::PKTS: return "Pkts";
        case Field::PKTS_RATE:
        case Field::PKTS_AVG: return "Pkts/s";
        case Field::PORT: return "Port";
        case Field::PROTO: return "Proto";
        case Field::TLS_VERSION: return "TLS Version";
        case Field::CIPHER_SUITE: return "Cipher Suite";
        case Field::REQ: return "Req";
        case Field::REQ_RATE:
        case Field::REQ_AVG: return "Req/s";
        case Field::RST: return "RST";
        case Field::RST_RATE:
        case Field::RST_AVG: return "RST/s";
        case Field::SRT: return "Srt";
        case Field::SRT_RATE:
        case Field::SRT_AVG: return "Srt/s";

        case Field::TOP_CLIENT_IPS_IP: return "ClientIP";
        case Field::TOP_CLIENT_IPS_PKTS: return "ClientPackets";
        case Field::TOP_CLIENT_IPS_BYTES: return "ClientBytes";
        case Field::TOP_CLIENT_IPS_REQUESTS: return "ClientRequests";

        case Field::SRT_P95: return "Srt95 (1s)";
        case Field::SRT_P99: return "Srt99 (1s)";
        case Field::SRT_MAX: return "SrtMax (1s)";

        case Field::SRT_TOTAL_P95: return "Srt95";
        case Field::SRT_TOTAL_P99: return "Srt99";
        case Field::SRT_TOTAL_MAX: return "SrtMax";

        case Field::RR_A_RATE: return "A";
        case Field::RR_AAAA_RATE: return "AAAA";
        case Field::RR_CNAME_RATE: return "CNAME";
        case Field::RR_PTR_RATE: return "PTR";
        case Field::RR_TXT_RATE: return "TXT";
        case Field::RR_OTHER_RATE: return "OTHER";

        case Field::RR_A_AVG: return "A";
        case Field::RR_AAAA_AVG: return "AAAA";
        case Field::RR_CNAME_AVG: return "CNAME";
        case Field::RR_PTR_AVG: return "PTR";
        case Field::RR_TXT_AVG: return "TXT";
        case Field::RR_OTHER_AVG: return "OTHER";

        case Field::DS_P95: return "Ds95 (1s)";
        case Field::DS_P99: return "Ds99 (1s)";
        case Field::DS_MAX: return "DsMax (1s)";

        case Field::DS_TOTAL_P95: return "Ds95";
        case Field::DS_TOTAL_P99: return "Ds99";
        case Field::DS_TOTAL_MAX: return "DsMax";

        case Field::SYN: return "SYN";
        case Field::SYN_RATE:
        case Field::SYN_AVG: return "SYN/s";
        case Field::SYNACK: return "SYNACK";
        case Field::SYNACK_RATE:
        case Field::SYNACK_AVG: return "SYNACK/s";
        case Field::TIMEOUTS: return "Tmo";
        case Field::TIMEOUTS_RATE:
        case Field::TIMEOUTS_AVG: return "Tmo/s";
        case Field::TRUNC: return "Trunc";
        case Field::TYPE: return "Type";
        case Field::ZWIN: return "0win";
        case Field::ZWIN_RATE:
        case Field::ZWIN_AVG: return "0win/s";
        default:
            return "Unknown";
    }
}

auto fieldToInitialSize(Field field) -> int
{
    switch (field) {
        case Field::FQDN: return 42;
        case Field::TRUNC: return 6;
        case Field::TYPE: return 6;
        case Field::DIR: return 6;

        case Field::DOMAIN: return 34;
        case Field::CIPHER_SUITE: return 38;

        case Field::BYTES: return 12;

        case Field::TOP_CLIENT_IPS_IP: return 24;
        case Field::TOP_CLIENT_IPS_PKTS: return 18;
        case Field::TOP_CLIENT_IPS_BYTES: return 18;
        case Field::TOP_CLIENT_IPS_REQUESTS: return 18;

        case Field::IP: return 16;

        case Field::PORT: return 5;
        case Field::PROTO: return 5;
        default: return 12;
    }
}

auto rateModeToDescription(RateMode rateMode) -> std::string
{
    switch (rateMode) {
        case RateMode::LAST_SECOND:
            return "Last second average";
        case RateMode::AVG:
            return "Global average";
    }
}

auto headerToSize(Header header) -> int {
    switch (header) {
        case Header::PROTOCOL_KEY: return 10;
        case Header::DISPLAY_KEY: return 10;
        case Header::PROTOCOL_VALUE: return 20;
        case Header::DISPLAY_VALUE: return 20;
    };
}

} // namespace flowstats
