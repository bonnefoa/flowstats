#pragma once
#include "enum.h"

namespace flowstats {
#define FQDN_SIZE 42
#define IP_SIZE 16
#define LEFT_ALIGN(size) "{:<" STR(size) "." STR(size) "} "

BETTER_ENUM(Field, char,
    DIR,
    DOMAIN,
    FQDN,
    IP,
    PORT,
    PROTO,

    ACTIVE_CONNECTIONS,
    FAILED_CONNECTIONS,
    CLOSE,
    CLOSE_RATE,
    CONN,
    CONN_RATE,
    CT_P95,
    CT_P99,

    RCRD_AVG,
    TOP_CLIENT_IPS,
    REQ,
    REQ_RATE,
    REQ_AVG,

    SRT,
    SRT_RATE,
    SRT_P95,
    SRT_P99,
    SRT_MAX,

    DS_P95,
    DS_P99,
    DS_MAX,

    MTU,
    PKTS,
    PKTS_RATE,
    PKTS_AVG,
    BYTES,
    BYTES_RATE,
    BYTES_AVG,

    SYN,
    SYN_RATE,
    SYNACK,
    SYNACK_RATE,
    ZWIN,
    ZWIN_RATE,
    RST,
    RST_RATE,
    FIN,
    FIN_RATE,

    TIMEOUTS,
    TIMEOUTS_RATE,
    TRUNC,
    TYPE);

auto fieldToSortable(Field field) -> bool;
auto fieldToHeader(Field field) -> char const*;

} // namespace flowstats
