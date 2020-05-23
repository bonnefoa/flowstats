#include "SslProto.hpp"

namespace flowstats {

#define SSL_SERVER_NAME_EXT 0
#define SSL_SNI_HOST_NAME 0

auto checkValidSslVersion(uint16_t sslVersion) -> bool
{
    if (sslVersion != SSL3 && sslVersion != TLS1_0 && sslVersion != TLS1_1 && sslVersion != TLS1_2) {
        return false;
    }
    return true;
}

auto checkValidSsl(Cursor* cursor) -> bool
{
    uint8_t recordType = cursor->readUint8();
    if (recordType != SSL_CHANGE_CIPHER_SPEC && recordType != SSL_ALERT && recordType != SSL_HANDSHAKE && recordType != SSL_APPLICATION_DATA) {
        return false;
    }
    auto sslVersion = cursor->readUint16();
    if (checkValidSslVersion(sslVersion) == false) {
        return false;
    }
    auto length = cursor->readUint16();
    if (cursor->remainingBytes() < length) {
        return false;
    }
    return true;
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

auto checkSslHandshake(Cursor* cursor) -> bool
{
    uint8_t recordType = cursor->readUint8();
    if (recordType != SSL_HANDSHAKE) {
        return false;
    }
    cursor->skipUint16();
    cursor->skipUint16();
    return true;
}

auto checkSslChangeCipherSpec(Cursor* cursor) -> bool
{
    uint8_t recordType = cursor->readUint8();
    if (recordType != SSL_CHANGE_CIPHER_SPEC) {
        return false;
    }
    auto sslVersion = cursor->readUint16();
    if (checkValidSslVersion(sslVersion) == false) {
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
