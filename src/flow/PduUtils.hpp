#pragma once

#include <ip.h>
#include <tcp.h>

namespace flowstats {

auto getTcpPayloadSize(const Tins::IP& ip, const Tins::TCP& tcp) -> int;

class payload_too_small : public std::runtime_error {
public:
    payload_too_small()
        : std::runtime_error("payload too small")
    {
    }
};

class Cursor {
public:
    Cursor(const std::vector<uint8_t>& payload)
        : payload(payload) {};
    virtual ~Cursor() = default;

    auto remainingBytes() -> int { return payload.size() - index; };
    auto readUint8() -> uint8_t;
    auto readUint16() -> uint16_t;
    auto readUint24() -> uint32_t;
    auto readUint32() -> uint32_t;

    auto skipUint8() -> void;
    auto skipUint16() -> void;
    auto skipUint24() -> void;
    auto skipUint32() -> void;
    auto checkSize(int size) -> void;

private:
    const std::vector<uint8_t>& payload;
    int index = 0;
};

} // flowstats
