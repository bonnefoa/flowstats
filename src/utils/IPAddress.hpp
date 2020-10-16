#pragma once
#include <tins/ip.h>
#include <tins/ip_address.h>
#include <tins/ipv6_address.h>
#include <tins/memory_helpers.h>

namespace flowstats {

class IPAddress {

public:
    IPAddress() = default;
    IPAddress(IPAddress const& other) = default;
    virtual ~IPAddress() = default;

    explicit IPAddress(Tins::IPv4Address ipv4)
    {
        Tins::Memory::OutputMemoryStream output(address.data(), address.size());
        output.write(ipv4);
        isV6 = false;
    };

    explicit IPAddress(Tins::IPv6Address ipv6)
    {
        Tins::Memory::OutputMemoryStream output(address.data(), address.size());
        output.write(ipv6);
        isV6 = true;
    };

    explicit IPAddress(std::array<uint8_t, 16> address)
        : address(address) {};

    [[nodiscard]] auto getIsV6() const -> bool { return isV6; };
    [[nodiscard]] auto getAddrV4() const -> Tins::IPv4Address;
    [[nodiscard]] auto getAddrV6() const -> Tins::IPv6Address;
    [[nodiscard]] auto getAddrStr() const -> std::string;

    auto operator<(IPAddress const& b) const -> bool
    {
        return address < b.address;
    }

    auto operator==(IPAddress const& b) const -> bool
    {
        return address == b.address;
    }

    auto operator=(IPAddress&& other) noexcept -> IPAddress&;
    auto operator=(IPAddress const& other) noexcept -> IPAddress& = default;

private:
    std::array<uint8_t, 16> address = {};
    bool isV6 = false;
};

typedef std::array<IPAddress, 2> IPAddressPair;

} // namespace flowstats

namespace std {

template <>
struct hash<flowstats::IPAddress> {
    auto operator()(const flowstats::IPAddress& addr) const -> size_t
    {
        if (addr.getIsV6()) {
            return std::hash<Tins::IPv6Address>()(addr.getAddrV6());
        }
        return std::hash<Tins::IPv4Address>()(addr.getAddrV4());
    }
};

} // namespace std
