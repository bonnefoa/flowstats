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
    case Field::TOP_CLIENT_IPS:
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
            default:
                break;
        }
    }
    return field;
}

auto fieldToHeader(Field field) -> char const*
{
    switch (field) {
    case Field::ACTIVE_CONNECTIONS:
        return "ActConn";
    case Field::FAILED_CONNECTIONS:
        return "FailConn";
    case Field::BYTES:
        return "Bytes";
    case Field::BYTES_RATE:
        return "Bytes/s";
    case Field::BYTES_AVG:
        return "Bytes/s";
    case Field::CLOSE:
        return "Close";
    case Field::CLOSE_RATE:
        return "Close/s";
    case Field::CLOSE_AVG:
        return "Close/s";
    case Field::CONN:
        return "Conn";
    case Field::CONN_RATE:
        return "Conn/s";
    case Field::CONN_AVG:
        return "Conn/s";
    case Field::CT_P95:
        return "CTp95 (1s)";
    case Field::CT_P99:
        return "CTp99 (1s)";
    case Field::CT_TOTAL_P95:
        return "CTp95";
    case Field::CT_TOTAL_P99:
        return "CTp99";
    case Field::DIR:
        return "Dir";
    case Field::DOMAIN:
        return "Domain";
    case Field::FIN:
        return "FIN";
    case Field::FIN_RATE:
        return "FIN/s";
    case Field::FIN_AVG:
        return "FIN/s";
    case Field::FQDN:
        return "Fqdn";
    case Field::IP:
        return "Ip";
    case Field::MTU:
        return "Mtu";
    case Field::PKTS:
        return "Pkts";
    case Field::PKTS_RATE:
        return "Pkts/s";
    case Field::PKTS_AVG:
        return "Pkts/s";
    case Field::PORT:
        return "Port";
    case Field::PROTO:
        return "Proto";
    case Field::TLS_VERSION:
        return "TLS Version";
    case Field::CIPHER_SUITE:
        return "Cipher Suite";
    case Field::RCRD_AVG:
        return "Rcrd";
    case Field::REQ:
        return "Req";
    case Field::REQ_RATE:
        return "Req/s";
    case Field::REQ_AVG:
        return "Req/s";
    case Field::RST:
        return "RST";
    case Field::RST_RATE:
        return "RST/s";
    case Field::RST_AVG:
        return "RST/s";
    case Field::SRT:
        return "Srt";
    case Field::SRT_RATE:
        return "Srt/s";
    case Field::SRT_AVG:
        return "Srt/s";

    case Field::TOP_PKTS_CLIENT_IPS:
        return "TopPktsClientIps";
    case Field::TOP_BYTES_CLIENT_IPS:
        return "TopBytesClientIps";
    case Field::TOP_CLIENT_IPS:
        return "TopClientIps";

    case Field::SRT_P95:
        return "Srt95 (1s)";
    case Field::SRT_P99:
        return "Srt99 (1s)";
    case Field::SRT_MAX:
        return "SrtMax (1s)";

    case Field::SRT_TOTAL_P95:
        return "Srt95";
    case Field::SRT_TOTAL_P99:
        return "Srt99";
    case Field::SRT_TOTAL_MAX:
        return "SrtMax";

    case Field::DS_P95:
        return "Ds95 (1s)";
    case Field::DS_P99:
        return "Ds99 (1s)";
    case Field::DS_MAX:
        return "DsMax (1s)";

    case Field::DS_TOTAL_P95:
        return "Ds95";
    case Field::DS_TOTAL_P99:
        return "Ds99";
    case Field::DS_TOTAL_MAX:
        return "DsMax";

    case Field::SYN:
        return "SYN";
    case Field::SYN_RATE:
        return "SYN/s";
    case Field::SYN_AVG:
        return "SYN/s";
    case Field::SYNACK:
        return "SYNACK";
    case Field::SYNACK_RATE:
        return "SYNACK/s";
    case Field::SYNACK_AVG:
        return "SYNACK/s";
    case Field::TIMEOUTS:
        return "Tmo";
    case Field::TIMEOUTS_RATE:
        return "Tmo/s";
    case Field::TIMEOUTS_AVG:
        return "Tmo/s";
    case Field::TRUNC:
        return "Trunc";
    case Field::TYPE:
        return "Type";
    case Field::ZWIN:
        return "0win";
    case Field::ZWIN_RATE:
        return "0win/s";
    case Field::ZWIN_AVG:
        return "0win/s";
    default:
        return "Unknown";
    }
}

auto rateModeToDescription(RateMode rateMode) -> std::string {
    switch (rateMode) {
        case RateMode::LAST_SECOND:
            return "Last second average";
        case RateMode::AVG:
            return "Global average";
    }
}

} // namespace flowstats
