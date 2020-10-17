#include "SslProto.hpp"

namespace flowstats {

#define SSL_SERVER_NAME_EXT 0
#define SSL_SNI_HOST_NAME 0

#define RETURN_EMPTY_IF_EMPTY(VAR) \
    if (!(VAR)) {                  \
        return {};                 \
    }

auto parseTlsVersion(Cursor* cursor) -> std::optional<TLSVersion>
{
    auto mbVersionInt = cursor->read_be<uint16_t>();
    RETURN_EMPTY_IF_EMPTY(mbVersionInt);
    auto mbVersion = TLSVersion::_from_integral_nothrow(mbVersionInt.value());
    RETURN_EMPTY_IF_EMPTY(mbVersion);
    return mbVersion.value();
}

auto getSslDomainFromSni(Cursor* cursor) -> std::optional<std::string>
{
    auto listLength = cursor->read_be<uint16_t>();
    RETURN_EMPTY_IF_EMPTY(listLength);

    auto listType = cursor->read<uint8_t>();
    RETURN_EMPTY_IF_EMPTY(listType);

    if (listType != SSL_SNI_HOST_NAME) {
        if (cursor->skip(listLength.value()) == false) {
            return {};
        }
        return "";
    }

    int initialReadListSize = cursor->remainingBytes();
    while ((initialReadListSize - cursor->remainingBytes()) < listLength) {
        auto serverNameLength = cursor->read_be<uint16_t>();
        if (serverNameLength.has_value() == false) {
            return {};
        }
        return cursor->readString(serverNameLength.value());
    }
    return "";
}

auto TlsHandshake::getSslDomainFromExtension(Cursor* cursor) -> std::optional<std::string>
{
    auto length = cursor->read_be<uint16_t>();
    int initialSize = cursor->remainingBytes();
    while ((initialSize - cursor->remainingBytes()) < length) {
        auto extensionType = cursor->read_be<uint16_t>();
        RETURN_EMPTY_IF_EMPTY(extensionType);

        auto extensionLength = cursor->read_be<uint16_t>();
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

auto checkSslChangeCipherSpec(Cursor* cursor) -> bool
{
    auto message = cursor->read<uint8_t>();
    if (message != 1) {
        return false;
    }
    return true;
}

auto TlsHeader::parse(Cursor* cursor) -> std::optional<TlsHeader>
{
    auto mbContentTypeInt = cursor->read<uint8_t>();
    RETURN_EMPTY_IF_EMPTY(mbContentTypeInt);
    auto mbContentType = SSLContentType::_from_integral_nothrow(mbContentTypeInt.value());
    RETURN_EMPTY_IF_EMPTY(mbContentType);

    auto mbVersion = parseTlsVersion(cursor);
    RETURN_EMPTY_IF_EMPTY(mbVersion);

    auto mbLengthInt = cursor->read_be<uint16_t>();
    RETURN_EMPTY_IF_EMPTY(mbLengthInt);
    auto length = mbLengthInt.value();
    if (cursor->remainingBytes() < length) {
        return {};
    }
    return TlsHeader(mbContentType.value(), mbVersion.value());
}

auto TlsHandshake::parse(Cursor* cursor) -> std::optional<TlsHandshake>
{
    auto mbHandshakeTypeInt = cursor->read<uint8_t>();
    RETURN_EMPTY_IF_EMPTY(mbHandshakeTypeInt);
    auto mbHandshakeType = SSLHandshakeType::_from_integral_nothrow(mbHandshakeTypeInt.value());
    RETURN_EMPTY_IF_EMPTY(mbHandshakeType);

    auto mbPduLength = cursor->readUint24();
    RETURN_EMPTY_IF_EMPTY(mbPduLength);
    auto pduLength = mbPduLength.value();
    if (cursor->checkSize(pduLength - 4) == false) {
        return {};
    };

    auto mbVersion = parseTlsVersion(cursor);
    RETURN_EMPTY_IF_EMPTY(mbVersion);

    auto tlsHandshake = TlsHandshake(mbHandshakeType.value(), pduLength, mbVersion.value(), cursor);

    return tlsHandshake;
}

TlsHandshake::TlsHandshake(SSLHandshakeType handshakeType, uint16_t length, TLSVersion version, Cursor* cursor)
    : handshakeType(handshakeType)
    , length(length)
    , version(version)
{

    if (handshakeType == +SSLHandshakeType::SSL_CLIENT_HELLO
        || handshakeType == +SSLHandshakeType::SSL_SERVER_HELLO) {
        // Random
        if (cursor->skip(32) == false) {
            return;
        };
        auto sessionIdLength = cursor->read<uint8_t>();
        if (cursor->skip(sessionIdLength) == false) {
            return;
        };
    }

    if (handshakeType == +SSLHandshakeType::SSL_CLIENT_HELLO) {
        auto cipherSuiteLength = cursor->read_be<uint16_t>();
        if (cursor->skip(cipherSuiteLength) == false) {
            return;
        };

        auto compressionMethodLength = cursor->read<uint8_t>();
        if (cursor->skip(compressionMethodLength) == false) {
            return;
        }

        auto extractedDomain = getSslDomainFromExtension(cursor);
        if (extractedDomain.value_or("") != "") {
            domain = extractedDomain.value();
        }
    } else if (handshakeType == +SSLHandshakeType::SSL_SERVER_HELLO) {
        auto mbCipherSuite = cursor->read_be<uint16_t>();
        if (!mbCipherSuite) {
            return;
        }
        auto mbSslCipherSuite = SSLCipherSuite::_from_integral_nothrow(mbCipherSuite.value());
        if (mbSslCipherSuite) {
            sslCipherSuite = mbSslCipherSuite.value();
        }
    }
};

} // namespace flowstats
