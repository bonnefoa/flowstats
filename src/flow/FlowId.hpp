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
using IPv4 = uint32_t;
using IPv6 = Tins::IPv6Address;
BETTER_ENUM(Transport, char, TCP, UDP);
BETTER_ENUM(Network, char, IPV6, IPV4);

struct FlowId {

    FlowId() = default;

    FlowId(FlowId&& flowId) noexcept;
    auto operator=(FlowId&& other) noexcept -> FlowId&;

    FlowId(FlowId const& flowId);
    auto operator=(FlowId const& other) noexcept -> FlowId&;

    FlowId(std::array<uint16_t, 2> ports, std::array<IPv4, 2> pktIps,
        Network network, Transport transport);
    FlowId(std::array<uint16_t, 2> ports, std::array<IPv6, 2> pktIps,
        Network network, Transport transport);

    FlowId(Tins::IP const* ip, Tins::IPv6 const* ipv6,
        Tins::TCP const* tcp, Tins::UDP const* udp);
    FlowId(Tins::IPv6 const& ip, Tins::TCP const& tcp);
    FlowId(Tins::IP const& ip, Tins::TCP const& tcp);
    FlowId(Tins::IPv6 const& ip, Tins::UDP const& udp);
    FlowId(Tins::IP const& ip, Tins::UDP const& udp);

    [[nodiscard]] auto toString() const -> std::string;
    [[nodiscard]] auto getIp(uint8_t pos) const { return ipv4[pos]; };
    [[nodiscard]] auto getIpv6(uint8_t pos) const { return ipv6[pos]; };

    [[nodiscard]] auto getPorts() const { return ports; };
    [[nodiscard]] auto getPort(uint8_t pos) const { return ports[pos]; };
    [[nodiscard]] auto getNetwork() const { return network; };
    [[nodiscard]] auto getTransport() const { return transport; };
    [[nodiscard]] auto getDirection() const { return direction; };

    [[nodiscard]] auto hash() const
    {
        if (network == +Network::IPV4) {
            return std::hash<IPv4>()(ipv4[0]) + std::hash<IPv4>()(ipv4[1]) + std::hash<uint16_t>()(ports[0]) + std::hash<uint16_t>()(ports[1]);
        } else {
            return std::hash<IPv6>()(ipv6[0]) + std::hash<IPv6>()(ipv6[1]) + std::hash<uint16_t>()(ports[0]) + std::hash<uint16_t>()(ports[1]);
        }
    };

private:
    union {
        std::array<IPv4, 2> ipv4;
        std::array<IPv6, 2> ipv6 = {};
    };
    std::array<Port, 2> ports = {};
    Network network = Network::IPV4;
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
        //+ std::hash<std::underlying_type<flowstats::Direction>::type>()(flowId.direction);
    }
};

} // namespace std
