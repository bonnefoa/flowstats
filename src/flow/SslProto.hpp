#pragma once
#include "PduUtils.hpp"

namespace flowstats {

enum SSLVersion {
    SSL2 = 0x0200,
    SSL3 = 0x0300,
    TLS1_0 = 0x0301,
    TLS1_1 = 0x0302,
    TLS1_2 = 0x0303
};

enum SSLHandshakeType {
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
};

enum SSLRecordType {
    SSL_CHANGE_CIPHER_SPEC = 20,
    SSL_ALERT = 21,
    SSL_HANDSHAKE = 22,
    SSL_APPLICATION_DATA = 23
};

[[nodiscard]] auto getSslDomainFromExtension(Cursor* cursor) -> std::string;
[[nodiscard]] auto checkValidSsl(Cursor* cursor) -> bool;
[[nodiscard]] auto checkValidSslVersion(uint16_t sslVersion) -> bool;
[[nodiscard]] auto checkSslHandshake(Cursor* cursor) -> bool;
[[nodiscard]] auto checkSslChangeCipherSpec(Cursor* cursor) -> bool;

} // namespace flowstats
