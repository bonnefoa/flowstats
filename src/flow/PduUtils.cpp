#include "PduUtils.hpp"

namespace flowstats {

auto getTcpPayloadSize(Tins::IP const* ip, Tins::IPv6 const* ipv6,
    Tins::TCP const& tcp) -> uint32_t
{
    if (ip) {
        return ip->advertised_size() - ip->header_size() - tcp.header_size();
    } else if (ipv6) {
        return ipv6->advertised_size() - ipv6->header_size() - tcp.header_size();
    }
    return 0;
}

auto Cursor::checkSize(uint32_t size) -> bool
{
    if (payload.size() - index < size) {
        return false;
    }
    return true;
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
