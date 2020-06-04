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
using IPv4 = Tins::IPv4Address;
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
    [[nodiscard]] auto getIp(uint8_t pos) const { return ip.ipv4[pos]; };
    [[nodiscard]] auto getIpv6(uint8_t pos) const { return ip.ipv6[pos]; };

    [[nodiscard]] auto getPorts() const { return ports; };
    [[nodiscard]] auto getPort(uint8_t pos) const { return ports[pos]; };
    [[nodiscard]] auto getNetwork() const { return network; };
    [[nodiscard]] auto getTransport() const { return transport; };
    [[nodiscard]] auto getDirection() const { return direction; };

    [[nodiscard]] auto hash() const
    {
        size_t ipHash = 0;
        if (network == +Network::IPV4) {
            ipHash = std::hash<IPv4>()(ip.ipv4[0]) + std::hash<IPv4>()(ip.ipv4[1]);
        } else {
            ipHash = std::hash<IPv6>()(ip.ipv6[0]) + std::hash<IPv6>()(ip.ipv6[1]);
        }
        return ipHash
            + std::hash<uint16_t>()(ports[0]) + std::hash<uint16_t>()(ports[1])
            + std::hash<uint8_t>()(network)
            + std::hash<uint8_t>()(transport);
    };

    auto operator<(FlowId const& b) const -> bool
    {
        bool ipRes = false;
        if (network == +Network::IPV4) {
            ipRes = ip.ipv4 < b.ip.ipv4;
        } else {
            ipRes = ip.ipv6 < b.ip.ipv6;
        }

        return ipRes
            && ports < b.ports
            && network < b.network
            && transport < b.transport;
    }

    auto operator==(FlowId const& b) const -> bool
    {
        bool ipRes = false;
        if (network == +Network::IPV4) {
            ipRes = ip.ipv4 == b.ip.ipv4;
        } else {
            ipRes = ip.ipv6 == b.ip.ipv6;
        }
        return ipRes
            && ports == b.ports
            && network == b.network
            && transport == b.transport;
    }

private:
    union IP {
        std::array<IPv4, 2> ipv4;
        std::array<IPv6, 2> ipv6;
        IP() { memset(this, 0, sizeof(IP)); }
    } ip;
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
    }
};

} // namespace std
