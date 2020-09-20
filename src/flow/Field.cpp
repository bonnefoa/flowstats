#include "Field.hpp"

namespace flowstats {

auto fieldToSortable(Field field) -> bool
{
    switch (field) {
    case Field::DIR:
    case Field::TOP_CLIENT_IPS:
    case Field::REQ_AVG:
    case Field::PKTS_AVG:
    case Field::BYTES_AVG:
        return false;
    default:
        return true;
    }
}

auto fieldWithRateMode(RateMode rateMode, Field field) -> Field
{
    if (rateMode == +RateMode::IMMEDIATE) {
        switch (field) {
            case Field::CLOSE:
                return Field::CLOSE_RATE;
            case Field::CONN:
                return Field::CONN_RATE;
            case Field::REQ:
                return Field::REQ_RATE;
            case Field::SRT:
                return Field::SRT_RATE;
            case Field::PKTS:
                return Field::PKTS_RATE;
            case Field::BYTES:
                return Field::BYTES_RATE;
            case Field::SYN:
                return Field::SYN_RATE;
            case Field::SYNACK:
                return Field::SYNACK_RATE;
            case Field::ZWIN:
                return Field::ZWIN_RATE;
            case Field::RST:
                return Field::RST_RATE;
            case Field::FIN:
                return Field::FIN_RATE;
            case Field::TIMEOUTS:
                return Field::TIMEOUTS_RATE;
            default:
                return field;
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
        return "Bytes Total";
    case Field::BYTES_RATE:
        return "Bytes/s";
    case Field::BYTES_AVG:
        return "Bytes Avg";
    case Field::CLOSE:
        return "Close Total";
    case Field::CLOSE_RATE:
        return "Close/s";
    case Field::CONN:
        return "Conn Total";
    case Field::CONN_RATE:
        return "Conn/s";
    case Field::CT_P95:
        return "CTp95";
    case Field::CT_P99:
        return "CTp99";
    case Field::DIR:
        return "Dir";
    case Field::DOMAIN:
        return "Domain";
    case Field::FIN:
        return "FIN Total";
    case Field::FIN_RATE:
        return "FIN/s";
    case Field::FQDN:
        return "Fqdn";
    case Field::IP:
        return "Ip";
    case Field::MTU:
        return "Mtu";
    case Field::PKTS:
        return "Pkts Total";
    case Field::PKTS_RATE:
        return "Pkts/s";
    case Field::PKTS_AVG:
        return "Pkts Avg";
    case Field::PORT:
        return "Port";
    case Field::PROTO:
        return "Proto";
    case Field::TLS_VERSION:
        return "TLS Version";
    case Field::CIPHER_SUITE:
        return "Cipher Suite";
    case Field::RCRD_AVG:
        return "Rcrd avg";
    case Field::TOP_CLIENT_IPS:
        return "TopClientIps";
    case Field::REQ:
        return "Req Total";
    case Field::REQ_RATE:
        return "Req/s";
    case Field::REQ_AVG:
        return "ReqAvg";
    case Field::RST:
        return "RST Total";
    case Field::RST_RATE:
        return "RST/s";
    case Field::SRT:
        return "Srt Total";
    case Field::SRT_RATE:
        return "Srt/s";
    case Field::SRT_P95:
        return "Srt95";
    case Field::SRT_P99:
        return "Srt99";
    case Field::SRT_MAX:
        return "SrtMax";

    case Field::DS_P95:
        return "Ds95";
    case Field::DS_P99:
        return "Ds99";
    case Field::DS_MAX:
        return "DsMax";

    case Field::SYN:
        return "SYN Total";
    case Field::SYN_RATE:
        return "SYN/s";
    case Field::SYNACK:
        return "SYNACK Total";
    case Field::SYNACK_RATE:
        return "SYNACK/s";
    case Field::TIMEOUTS:
        return "Tmo Total";
    case Field::TIMEOUTS_RATE:
        return "Tmo/s";
    case Field::TRUNC:
        return "Trunc";
    case Field::TYPE:
        return "Type";
    case Field::ZWIN:
        return "0win Total";
    case Field::ZWIN_RATE:
        return "0win/s";
    default:
        return "Unknown";
    }
}

} // namespace flowstats
