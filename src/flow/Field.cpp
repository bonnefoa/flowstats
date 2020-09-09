#include "Field.hpp"

namespace flowstats {

auto fieldToFormat(Field field) -> char const*
{
    switch (field) {
    case Field::FQDN:
        return "{:<42.42} ";
    case Field::TRUNC:
    case Field::TYPE:
    case Field::DIR:
        return "{:<6.6} ";
    case Field::DOMAIN:
        return "{:<34.34} ";
    case Field::BYTES:
        return "{:<10.10} ";
    case Field::TOP_CLIENT_IPS:
        return "{:<60.60} ";
    case Field::IP:
        return "{:<16.16} ";
    case Field::PORT:
    case Field::PROTO:
        return "{:<5.5} ";
    default:
        return "{:<8.8} ";
    }
}

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
        return "BytesAvg";
    case Field::CLOSE:
        return "Close";
    case Field::CLOSE_RATE:
        return "Close/s";
    case Field::CONN:
        return "Conn";
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
        return "FIN";
    case Field::FIN_RATE:
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
        return "Pkts Avg";
    case Field::PORT:
        return "Port";
    case Field::PROTO:
        return "Proto";
    case Field::RCRD_AVG:
        return "Rcrd avg";
    case Field::TOP_CLIENT_IPS:
        return "TopClientIps";
    case Field::REQ:
        return "Req";
    case Field::REQ_RATE:
        return "Req/s";
    case Field::REQ_AVG:
        return "ReqAvg";
    case Field::RST:
        return "RST";
    case Field::RST_RATE:
        return "RST/s";
    case Field::SRT:
        return "Srt";
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
        return "SYN";
    case Field::SYN_RATE:
        return "SYN/s";
    case Field::SYNACK:
        return "SYNACK";
    case Field::SYNACK_RATE:
        return "SYNACK/s";
    case Field::TIMEOUTS:
        return "Tmo";
    case Field::TIMEOUTS_RATE:
        return "Tmo/s";
    case Field::TRUNC:
        return "Trunc";
    case Field::TYPE:
        return "Type";
    case Field::ZWIN:
        return "0win";
    case Field::ZWIN_RATE:
        return "0win/s";
    default:
        return "Unknown";
    }
}

} // namespace flowstats
