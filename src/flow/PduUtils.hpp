#pragma once

#include <tins/ip.h>
#include <tins/tcp.h>

namespace flowstats {

auto getTcpPayloadSize(Tins::IP const& ip, Tins::TCP const& tcp) -> uint32_t;

class payload_too_small : public std::runtime_error {
public:
    payload_too_small()
        : std::runtime_error("payload too small")
    {
    }
};

class Cursor {
public:
    explicit Cursor(std::vector<uint8_t> const& payload)
        : payload(payload) {};
    virtual ~Cursor() = default;

    auto remainingBytes() -> int { return payload.size() - index; };
    auto readUint8() -> uint8_t;
    auto readUint16() -> uint16_t;
    auto readUint24() -> uint32_t;
    auto readUint32() -> uint32_t;
    auto readString(int n) -> std::string;

    auto skip(int n) -> void;
    auto skipUint8() -> void;
    auto skipUint16() -> void;
    auto skipUint24() -> void;
    auto skipUint32() -> void;
    auto checkSize(int size) -> void;

private:
    std::vector<uint8_t> const& payload;
    int index = 0;
};

} // namespace flowstats
