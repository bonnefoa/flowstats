#pragma once

#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/udp.h>

namespace flowstats {

auto getTcpPayloadSize(Tins::IP const& ip, Tins::TCP const& tcp) -> uint32_t;

class Cursor {
public:
    explicit Cursor(std::vector<uint8_t> const& payload)
        : payload(payload) {};
    virtual ~Cursor() = default;

    auto remainingBytes() -> uint32_t { return payload.size() - index; };

    [[nodiscard]] auto readUint8() -> std::optional<uint8_t>;
    [[nodiscard]] auto readUint16() -> std::optional<uint16_t>;
    [[nodiscard]] auto readUint24() -> std::optional<uint32_t>;
    [[nodiscard]] auto readUint32() -> std::optional<uint32_t>;
    [[nodiscard]] auto readString(int n) -> std::optional<std::string>;

    [[nodiscard]] auto skip(std::optional<int> n) -> bool;
    [[nodiscard]] auto skip(int n) -> bool;
    [[nodiscard]] auto skipUint8() -> bool;
    [[nodiscard]] auto skipUint16() -> bool;
    [[nodiscard]] auto skipUint24() -> bool;
    [[nodiscard]] auto skipUint32() -> bool;
    [[nodiscard]] auto checkSize(uint32_t size) -> bool;

private:
    std::vector<uint8_t> const& payload;
    int index = 0;
};

auto getPorts(Tins::TCP const* tcp, Tins::UDP const* udp) -> std::array<int, 2>;

} // namespace flowstats
