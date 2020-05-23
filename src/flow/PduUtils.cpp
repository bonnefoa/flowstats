#include "PduUtils.hpp"

namespace flowstats {

auto getTcpPayloadSize(const Tins::IP& ip, const Tins::TCP& tcp) -> uint32_t
{
    return ip.advertised_size() - ip.header_size() - tcp.header_size();
}

auto Cursor::checkSize(uint32_t size) -> bool
{
    if (payload.size() - index < size) {
        return false;
    }
    return true;
}

auto Cursor::readUint8() -> std::optional<uint8_t>
{
    if (checkSize(1) == false) {
        return {};
    };
    return payload[index++];
}

auto Cursor::readUint16() -> std::optional<uint16_t>
{
    if (checkSize(2) == false) {
        return {};
    }
    auto res = (payload[index] << 8) + (payload[index + 1]);
    index += 2;
    return res;
}

auto Cursor::readUint24() -> std::optional<uint32_t>
{
    if (checkSize(3) == false) {
        return {};
    }
    auto res = (payload[index] << 16) + (payload[index + 1] << 8) + (payload[index + 2]);
    index += 3;
    return res;
}

auto Cursor::readUint32() -> std::optional<uint32_t>
{
    if (checkSize(4) == false) {
        return {};
    }
    auto res = (payload[index] << 24) + (payload[index + 1] << 16) + (payload[index + 2] << 8) + (payload[index + 3] << 0);

    index += 4;
    return res;
}

auto Cursor::readString(int n) -> std::optional<std::string>
{
    if (checkSize(n) == false) {
        return {};
    }
    std::string res(n, 'x');
    for (int i = 0; i < n; ++i) {
        res[i] = payload[index + i];
    }
    index += n;
    return res;
}

auto Cursor::skip(std::optional<int> n) -> bool
{
    if (n.has_value() == false) {
        return false;
    }
    return skip(n.value());
}

auto Cursor::skip(int n) -> bool
{
    if (checkSize(n) == false) {
        return false;
    }
    index += n;
    return true;
}

auto Cursor::skipUint8() -> bool
{
    return skip(1);
}

auto Cursor::skipUint16() -> bool
{
    return skip(2);
}

auto Cursor::skipUint24() -> bool
{
    return skip(3);
}

auto Cursor::skipUint32() -> bool
{
    return skip(4);
}

auto getPorts(Tins::TCP const* tcp, Tins::UDP const* udp) -> std::array<int, 2>
{
    if (tcp) {
        return { tcp->sport(), tcp->dport() };
    }
    if (udp) {
        return { udp->sport(), udp->dport() };
    }
    return {};
}

} // namespace flowstats
