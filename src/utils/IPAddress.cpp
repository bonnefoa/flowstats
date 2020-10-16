#include "IPAddress.hpp"
#include <functional>

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

auto IPAddress::operator=(IPAddress&& ipAddress) noexcept -> IPAddress&
{
    if (this == &ipAddress) {
        return *this;
    }
    address = ipAddress.address;
    isV6 = ipAddress.isV6;
    return *this;
}

} // namespace flowstats
