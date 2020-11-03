#pragma once
#include "Utils.hpp"
#include "enum.h"
#include <arpa/inet.h>
#include <sstream>
#include <tins/ip.h>
#include <tins/ipv6.h>
#include <tins/tcp.h>
#include <tins/udp.h>

namespace flowstats {

using Port = uint16_t;
// NOLINTNEXTLINE
BETTER_ENUM(Transport, char, TCP, UDP);

struct FlowId {

    FlowId() = default;

    FlowId(FlowId&& flowId) noexcept;
    auto operator=(FlowId&& other) noexcept -> FlowId&;

    FlowId(FlowId const& flowId);
    auto operator=(FlowId const& other) noexcept -> FlowId&;

    FlowId(Tins::IP const* ip, Tins::IPv6 const* ipv6,
        Tins::TCP const* tcp, Tins::UDP const* udp);

    FlowId(std::array<uint16_t, 2> ports,
        IPAddressPair const& pair, Transport transport);
    FlowId(IPAddressPair const& pair, Tins::TCP const& tcp);
    FlowId(IPAddressPair const& pair, Tins::UDP const& udp);

    [[nodiscard]] auto toString() const -> std::string;
    [[nodiscard]] auto getIp(uint8_t pos) const { return addressPair[pos]; };
    [[nodiscard]] auto getIpv4(uint8_t pos) const { return addressPair[pos].getAddrV4(); };
    [[nodiscard]] auto getIpv6(uint8_t pos) const { return addressPair[pos].getAddrV6(); };

    [[nodiscard]] auto getPorts() const { return ports; };
    [[nodiscard]] auto getPort(uint8_t pos) const { return ports[pos]; };
    [[nodiscard]] auto getTransport() const { return transport; };
    [[nodiscard]] auto getDirection() const { return direction; };

    [[nodiscard]] auto hash() const
    {
        return std::hash<IPAddress>()(addressPair[0]) + std::hash<IPAddress>()(addressPair[1]) + +std::hash<uint16_t>()(ports[0]) + std::hash<uint16_t>()(ports[1])
            + std::hash<uint8_t>()(transport);
    };

    auto operator<(FlowId const& b) const -> bool
    {
        return addressPair < b.addressPair
            && ports < b.ports
            && transport < b.transport;
    }

    auto operator==(FlowId const& b) const -> bool
    {
        return addressPair == b.addressPair
            && ports == b.ports
            && transport == b.transport;
    }

private:
    IPAddressPair addressPair;
    std::array<Port, 2> ports = {};
    Transport transport = Transport::TCP;
    Direction direction = FROM_CLIENT;
};
} // namespace flowstats

namespace std {

template <>
struct hash<flowstats::FlowId> {
    auto operator()(const flowstats::FlowId& flowId) const -> size_t
    {
        return flowId.hash();
    }
};

} // namespace std
