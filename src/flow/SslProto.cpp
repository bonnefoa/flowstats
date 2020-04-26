#include "SslProto.hpp"

namespace flowstats {

auto isValidSsl(Cursor* cursor) -> bool
{
    uint8_t recordType = cursor->readUint8();
    if (recordType != SSL_CHANGE_CIPHER_SPEC && recordType != SSL_ALERT && recordType != SSL_HANDSHAKE && recordType != SSL_APPLICATION_DATA) {
        return false;
    }
    auto sslVersion = cursor->readUint16();
    if (sslVersion != SSL3 && sslVersion != TLS1_0 && sslVersion != TLS1_1 && sslVersion != TLS1_2) {
        return false;
    }
    auto length = cursor->readUint16();
    if (cursor->remainingBytes() < length) {
        return false;
    }
    return true;
}

auto isSslHandshake(Cursor* cursor) -> bool
{
    uint8_t recordType = cursor->readUint8();
    if (recordType != SSL_HANDSHAKE) {
        return false;
    }
    cursor->skipUint16();
    cursor->skipUint16();
    return true;
}

auto isSslChangeCipherSpec(Cursor* cursor) -> bool
{
    uint8_t recordType = cursor->readUint8();
    if (recordType != SSL_CHANGE_CIPHER_SPEC) {
        return false;
    }
    auto sslVersion = cursor->readUint16();
    if (sslVersion != SSL3 && sslVersion != TLS1_0 && sslVersion != TLS1_1 && sslVersion != TLS1_2) {
        return false;
    }
    auto length = cursor->readUint16();
    if (length != 1) {
        return false;
    }
    auto message = cursor->readUint8();
    if (message != 1) {
        return false;
    }
    return true;
}

} // namespace flowstats
