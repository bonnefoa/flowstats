#include "SslProto.hpp"

namespace flowstats {

#define SSL_SERVER_NAME_EXT 0
#define SSL_SNI_HOST_NAME 0

auto checkValidSslVersion(uint16_t sslVersion) -> void
{
    if (sslVersion != SSL3 && sslVersion != TLS1_0 && sslVersion != TLS1_1 && sslVersion != TLS1_2) {
        throw Tins::malformed_packet();
    }
}

auto checkValidSsl(Cursor* cursor) -> void
{
    uint8_t recordType = cursor->readUint8();
    if (recordType != SSL_CHANGE_CIPHER_SPEC && recordType != SSL_ALERT && recordType != SSL_HANDSHAKE && recordType != SSL_APPLICATION_DATA) {
        throw Tins::malformed_packet();
    }
    auto sslVersion = cursor->readUint16();
    checkValidSslVersion(sslVersion);
    auto length = cursor->readUint16();
    if (cursor->remainingBytes() < length) {
        throw Tins::malformed_packet();
    }
}

auto getSslDomainFromSni(Cursor* cursor) -> std::string
{
    auto listLength = cursor->readUint16();
    auto listType = cursor->readUint8();
    if (listType != SSL_SNI_HOST_NAME) {
        cursor->skip(listLength);
        return "";
    }

    int initialReadListSize = cursor->remainingBytes();
    while ((initialReadListSize - cursor->remainingBytes()) < listLength) {
        auto serverNameLength = cursor->readUint16();
        return cursor->readString(serverNameLength);
    }
    return "";
}

auto getSslDomainFromExtension(Cursor* cursor) -> std::string
{
    auto length = cursor->readUint16();
    int initialSize = cursor->remainingBytes();
    while ((initialSize - cursor->remainingBytes()) < length) {
        auto extensionType = cursor->readUint16();
        auto extensionLength = cursor->readUint16();
        if (extensionType != SSL_SERVER_NAME_EXT) {
            cursor->skip(extensionLength);
            continue;
        }
        return getSslDomainFromSni(cursor);
    }
    return "";
}

auto checkSslHandshake(Cursor* cursor) -> void
{
    uint8_t recordType = cursor->readUint8();
    if (recordType != SSL_HANDSHAKE) {
        throw Tins::malformed_packet();
    }
    cursor->skipUint16();
    cursor->skipUint16();
}

auto checkSslChangeCipherSpec(Cursor* cursor) -> void
{
    uint8_t recordType = cursor->readUint8();
    if (recordType != SSL_CHANGE_CIPHER_SPEC) {
        throw Tins::malformed_packet();
    }
    auto sslVersion = cursor->readUint16();
    checkValidSslVersion(sslVersion);
    auto length = cursor->readUint16();
    if (length != 1) {
        throw Tins::malformed_packet();
    }
    auto message = cursor->readUint8();
    if (message != 1) {
        throw Tins::malformed_packet();
    }
}

} // namespace flowstats
