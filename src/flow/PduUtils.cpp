#include "PduUtils.hpp"

namespace flowstats {

auto getTcpPayloadSize(const Tins::IP& ip, const Tins::TCP& tcp) -> int
{
    return ip.advertised_size() - ip.header_size() - tcp.header_size();
}

auto Cursor::checkSize(int size) -> void
{
    if (payload.size() - index < size) {
        throw payload_too_small();
    }
}

auto Cursor::readUint8() -> uint8_t
{
    checkSize(1);
    return payload[index++];
}

auto Cursor::readUint16() -> uint16_t
{
    checkSize(2);
    auto res = (payload[index] << 8) + (payload[index + 1]);
    index += 2;
    return res;
}

auto Cursor::readUint24() -> uint32_t
{
    checkSize(3);
    auto res = (payload[index] << 16) + (payload[index + 1] << 8) + (payload[index + 2]);
    index += 3;
    return res;
}

auto Cursor::readUint32() -> uint32_t
{
    checkSize(4);
    auto res = (payload[index] << 24) + (payload[index + 1] << 16) + (payload[index + 2] << 8) + (payload[index + 3] << 0);

    index += 4;
    return res;
}

auto Cursor::skipUint8() -> void
{
    checkSize(1);
    index += 1;
}

auto Cursor::skipUint16() -> void
{
    checkSize(2);
    index += 2;
}

auto Cursor::skipUint24() -> void
{
    checkSize(3);
    index += 3;
}

auto Cursor::skipUint32() -> void
{
    checkSize(4);
    index += 4;
}

} // flowstats
