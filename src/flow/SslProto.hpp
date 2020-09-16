#pragma once
#include "PduUtils.hpp"
#include "enum.h"

namespace flowstats {

BETTER_ENUM(TLSVersion, uint16_t,
    UNKNOWN = 0x0000,
    SSL2 = 0x0200,
    SSL3 = 0x0300,
    TLS1_0 = 0x0301,
    TLS1_1 = 0x0302,
    TLS1_2 = 0x0303);

BETTER_ENUM(SSLHandshakeType, uint8_t,
    SSL_HELLO_REQUEST = 0,
    SSL_CLIENT_HELLO = 1,
    SSL_SERVER_HELLO = 2,
    SSL_NEW_SESSION_TICKET = 4,
    SSL_CERTIFICATE = 11,
    SSL_SERVER_KEY_EXCHANGE = 12,
    SSL_CERTIFICATE_REQUEST = 13,
    SSL_SERVER_DONE = 14,
    SSL_CERTIFICATE_VERIFY = 15,
    SSL_CLIENT_KEY_EXCHANGE = 16,
    SSL_FINISHED = 20,
    SSL_HANDSHAKE_UNKNOWN = 255
);

BETTER_ENUM(SSLContentType, uint8_t,
    SSL_CHANGE_CIPHER_SPEC = 20,
    SSL_ALERT = 21,
    SSL_HANDSHAKE = 22,
    SSL_APPLICATION_DATA = 23
);

struct TlsHeader {
    TlsHeader(SSLContentType contentType, TLSVersion version, uint16_t length)
        : contentType(contentType), version(version), length(length){};

    SSLContentType contentType;
    TLSVersion version;
    uint16_t length;

    static auto parse(Cursor *cursor) -> std::optional<TlsHeader>;
};

struct TlsHandshake {
public:
    TlsHandshake(SSLHandshakeType handshakeType, uint16_t length, TLSVersion version, Cursor *cursor);

    SSLHandshakeType handshakeType;
    uint16_t length;
    TLSVersion version;

    std::string domain;

    static auto parse(Cursor *cursor) -> std::optional<TlsHandshake>;

private:
    auto processClientHello(Cursor *cursor) -> void;
};

[[nodiscard]] auto getSslDomainFromExtension(Cursor* cursor) -> std::optional<std::string>;
[[nodiscard]] auto checkValidSsl(std::vector<uint8_t> const& payload) -> bool;
[[nodiscard]] auto checkValidSslVersion(std::optional<uint16_t> tlsVersion) -> std::optional<TLSVersion>;
[[nodiscard]] auto checkSslHandshake(Cursor* cursor) -> bool;
[[nodiscard]] auto checkSslChangeCipherSpec(Cursor* cursor) -> bool;

} // namespace flowstats
