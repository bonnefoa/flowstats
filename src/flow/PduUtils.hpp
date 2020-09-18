#pragma once

#include <tins/endianness.h>
#include <tins/ip.h>
#include <tins/ipv6.h>
#include <tins/tcp.h>
#include <tins/udp.h>

namespace flowstats {

auto getTcpPayloadSize(Tins::IP const* ip,
    Tins::IPv6 const* ipv6,
    Tins::TCP const& tcp) -> uint32_t;

class Cursor {
public:
    explicit Cursor(std::vector<uint8_t> const& payload)
        : payload(payload) {};
    virtual ~Cursor() = default;

    auto remainingBytes() -> uint32_t { return payload.size() - index; };

    template <typename T>
    [[nodiscard]] auto read() -> std::optional<T>
    {
        T value;
        auto sizeValue = sizeof(value);
        if (!checkSize(sizeValue)) {
            return {};
        }
        std::memcpy(&value, &payload[index], sizeValue);
        if (!skip(sizeValue)) {
            return {};
        };
        return value;
    }

    template <typename T>
    [[nodiscard]] auto read_be() -> std::optional<T>
    {
        auto res = read<T>();
        if (!res) {
            return {};
        };
        return Tins::Endian::be_to_host(*res);
    }

    [[nodiscard]] auto readUint24() -> std::optional<uint32_t>;
    [[nodiscard]] auto readString(int n) -> std::optional<std::string>;

    [[nodiscard]] auto skip(std::optional<int> n) -> bool;
    [[nodiscard]] auto skip(int n) -> bool;
    [[nodiscard]] auto checkSize(uint32_t size) -> bool;

private:
    std::vector<uint8_t> const& payload;
    int index = 0;
};

auto getPorts(Tins::TCP const* tcp, Tins::UDP const* udp) -> std::array<int, 2>;

} // namespace flowstats
