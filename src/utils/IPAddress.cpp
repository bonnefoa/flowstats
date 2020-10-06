#include "IPAddress.hpp"

namespace flowstats {

auto IPAddress::getAddrStr() const -> std::string
{
    return getAddrV4().to_string();
}

auto IPAddress::getAddrV4() const -> Tins::IPv4Address
{
    Tins::Memory::InputMemoryStream stream(address.data(), address.size());
    return stream.read<Tins::IPv4Address>();
}

auto IPAddress::getAddrV6() const -> Tins::IPv6Address
{
    Tins::Memory::InputMemoryStream stream(address.data(), address.size());
    return stream.read<Tins::IPv6Address>();
}

} // namespace std
