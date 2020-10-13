#pragma once
#include <tins/ip.h>
#include <tins/ip_address.h>
#include <tins/ipv6_address.h>
#include <tins/memory_helpers.h>

namespace flowstats {

class IPAddress {

public:
    IPAddress() = default;
    IPAddress(Tins::IPv4Address ipv4)
    {
        Tins::Memory::OutputMemoryStream output(address.data(), address.size());
        output.write(ipv4);
        isV6 = false;
    };

    IPAddress(Tins::IPv6Address ipv6)
    {
        Tins::Memory::OutputMemoryStream output(address.data(), address.size());
        output.write(ipv6);
        isV6 = true;
    };

    IPAddress(std::array<uint8_t, 16> address)
        : address(address) {};

    auto getAddrV4() const -> Tins::IPv4Address;
    auto getAddrV6() const -> Tins::IPv6Address;
    auto getAddrStr() const -> std::string;

    auto operator<(IPAddress const& b) const -> bool
    {
        return address < b.address;
    }

private:
    std::array<uint8_t, 16> address;
    bool isV6 = false;
};

} // namespace std
