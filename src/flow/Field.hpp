#pragma once
#include "enum.h"

namespace flowstats {
#define FQDN_SIZE 42
#define IP_SIZE 16
#define LEFT_ALIGN(size) "{:<" STR(size) "." STR(size) "} "

// NOLINTNEXTLINE
BETTER_ENUM(RateMode, uint8_t,
    LAST_SECOND,
    AVG);

// NOLINTNEXTLINE
BETTER_ENUM(Header, char,
    PROTOCOL_KEY,
    PROTOCOL_VALUE,
    DISPLAY_KEY,
    DISPLAY_VALUE
    );

// NOLINTNEXTLINE
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

    TOP_CLIENT_IPS_IP,
    TOP_CLIENT_IPS_BYTES,
    TOP_CLIENT_IPS_PKTS,
    TOP_CLIENT_IPS_REQUESTS,

    RR_A_RATE,
    RR_AAAA_RATE,
    RR_CNAME_RATE,
    RR_PTR_RATE,
    RR_TXT_RATE,
    RR_OTHER_RATE,

    RR_A_AVG,
    RR_AAAA_AVG,
    RR_CNAME_AVG,
    RR_PTR_AVG,
    RR_TXT_AVG,
    RR_OTHER_AVG,

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
auto fieldWithSubfields(Field field) -> bool;
auto fieldToInitialSize(Field field) -> int;

auto fieldWithRateMode(RateMode rateMode, Field field) -> Field;
auto rateModeToDescription(RateMode rateMode) -> std::string;

auto headerToSize(Header header) -> int;

} // namespace flowstats
