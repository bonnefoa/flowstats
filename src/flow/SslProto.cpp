#include "SslProto.hpp"

namespace flowstats {

#define SSL_SERVER_NAME_EXT 0
#define SSL_SNI_HOST_NAME 0

#define RETURN_FALSE_IF_EMPTY(VAR)    \
    if ((VAR).has_value() == false) { \
        return false;                 \
    }

#define RETURN_EMPTY_IF_EMPTY(VAR)    \
    if ((VAR).has_value() == false) { \
        return {};                    \
    }

auto checkValidSslVersion(std::optional<uint16_t> sslVersion) -> bool
{
    if (sslVersion == SSL3 || sslVersion == TLS1_0 || sslVersion == TLS1_1 || sslVersion == TLS1_2) {
        return true;
    }
    return false;
}

auto checkRecordType(std::optional<uint8_t> recordType) -> bool
{
    if (recordType == SSL_CHANGE_CIPHER_SPEC || recordType == SSL_ALERT || recordType == SSL_HANDSHAKE || recordType == SSL_APPLICATION_DATA) {
        return true;
    }
    return false;
}

auto checkValidSsl(Cursor* cursor) -> bool
{
    auto recordType = cursor->readUint8();
    RETURN_FALSE_IF_EMPTY(recordType);
    auto sslVersion = cursor->readUint16();
    RETURN_FALSE_IF_EMPTY(sslVersion);

    auto length = cursor->readUint16();
    if (cursor->remainingBytes() < length) {
        return false;
    }
    return true;
}

auto getSslDomainFromSni(Cursor* cursor) -> std::optional<std::string>
{
    auto listLength = cursor->readUint16();
    RETURN_EMPTY_IF_EMPTY(listLength);

    auto listType = cursor->readUint8();
    RETURN_EMPTY_IF_EMPTY(listType);

    if (listType != SSL_SNI_HOST_NAME) {
        if (cursor->skip(listLength.value()) == false) {
            return {};
        }
        return "";
    }

    int initialReadListSize = cursor->remainingBytes();
    while ((initialReadListSize - cursor->remainingBytes()) < listLength) {
        auto serverNameLength = cursor->readUint16();
        if (serverNameLength.has_value() == false) {
            return {};
        }
        return cursor->readString(serverNameLength.value());
    }
    return "";
}

auto getSslDomainFromExtension(Cursor* cursor) -> std::optional<std::string>
{
    auto length = cursor->readUint16();
    int initialSize = cursor->remainingBytes();
    while ((initialSize - cursor->remainingBytes()) < length) {
        auto extensionType = cursor->readUint16();
        RETURN_EMPTY_IF_EMPTY(extensionType);

        auto extensionLength = cursor->readUint16();
        RETURN_EMPTY_IF_EMPTY(extensionLength);
        if (extensionType != SSL_SERVER_NAME_EXT) {
            if (cursor->skip(extensionLength.value()) == false) {
                return {};
            }
            continue;
        }
        return getSslDomainFromSni(cursor);
    }
    return "";
}

auto checkSslHandshake(Cursor* cursor) -> bool
{
    auto recordType = cursor->readUint8();
    RETURN_FALSE_IF_EMPTY(recordType);
    if (recordType != SSL_HANDSHAKE) {
        return false;
    }
    // 2 uint16_t
    if (cursor->skip(4) == false) {
        return false;
    };
    return true;
}

auto checkSslChangeCipherSpec(Cursor* cursor) -> bool
{
    auto recordType = cursor->readUint8();
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
