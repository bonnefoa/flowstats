#pragma once
#include "enum.h"

namespace flowstats {
#define FQDN_SIZE 42
#define IP_SIZE 16
#define LEFT_ALIGN(size) "{:<" STR(size) "." STR(size) "} "

BETTER_ENUM(RateMode, uint8_t,
    LAST_SECOND,
    AVG);

BETTER_ENUM(Field, char,
    DIR,
    DOMAIN,
    FQDN,
    IP,
    PORT,
    PROTO,
    TLS_VERSION,
    CIPHER_SUITE,

    ACTIVE_CONNECTIONS,
    FAILED_CONNECTIONS,
    CLOSE,
    CLOSE_RATE,
    CLOSE_AVG,
    CONN,
    CONN_RATE,
    CONN_AVG,

    CT_P95,
    CT_P99,
    CT_TOTAL_P95,
    CT_TOTAL_P99,

    TOP_PKTS_CLIENT_IPS,
    TOP_BYTES_CLIENT_IPS,

    RCRD_AVG,
    TOP_CLIENT_IPS,
    REQ,
    REQ_RATE,
    REQ_AVG,

    SRT,
    SRT_RATE,
    SRT_AVG,

    SRT_P95,
    SRT_P99,
    SRT_MAX,

    SRT_TOTAL_P95,
    SRT_TOTAL_P99,
    SRT_TOTAL_MAX,

    DS_P95,
    DS_P99,
    DS_MAX,
    DS_TOTAL_P95,
    DS_TOTAL_P99,
    DS_TOTAL_MAX,

    MTU,
    PKTS,
    PKTS_RATE,
    PKTS_AVG,
    BYTES,
    BYTES_RATE,
    BYTES_AVG,

    SYN,
    SYN_RATE,
    SYN_AVG,
    SYNACK,
    SYNACK_RATE,
    SYNACK_AVG,
    ZWIN,
    ZWIN_RATE,
    ZWIN_AVG,
    RST,
    RST_RATE,
    RST_AVG,
    FIN,
    FIN_RATE,
    FIN_AVG,

    TIMEOUTS,
    TIMEOUTS_RATE,
    TIMEOUTS_AVG,
    TRUNC,
    TYPE);

auto fieldToSortable(Field field) -> bool;
auto fieldToHeader(Field field) -> char const*;
auto fieldWithRateMode(RateMode rateMode, Field field) -> Field;
auto rateModeToDescription(RateMode rateMode) -> std::string;

} // namespace flowstats
