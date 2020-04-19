#include "FlowId.hpp"
#include <fmt/format.h>

namespace flowstats {

auto FlowId::toString() -> std::string
{
    return fmt::format("{}:{} -> {}:{}",
        pcpp::IPv4Address(ips[direction]).toString(), ports[direction],
        pcpp::IPv4Address(ips[!direction]).toString(), ports[!direction]);
}

FlowId::FlowId(pcpp::IPv4Layer* ipv4Layer, pcpp::TcpLayer* tcpLayer)
{
    Port pktPorts[2] = { ntohs(tcpLayer->getTcpHeader()->portSrc), ntohs(tcpLayer->getTcpHeader()->portDst) };
    IPv4 pktIps[2] = { ipv4Layer->getIPv4Header()->ipSrc, ipv4Layer->getIPv4Header()->ipDst };
    *this = FlowId(pktPorts, pktIps);
}

FlowId::FlowId(pcpp::IPv4Layer* ipv4Layer, pcpp::UdpLayer* udpLayer)
{
    Port pktPorts[2] = { ntohs(udpLayer->getUdpHeader()->portSrc), ntohs(udpLayer->getUdpHeader()->portDst) };
    IPv4 pktIps[2] = { ipv4Layer->getIPv4Header()->ipSrc, ipv4Layer->getIPv4Header()->ipDst };
    *this = FlowId(pktPorts, pktIps);
}

FlowId::FlowId(pcpp::Packet* packet)
{
    if (packet->isPacketOfType(pcpp::TCP)) {
        auto* tcpLayer = packet->getLayerOfType<pcpp::TcpLayer>();
        auto* ipv4Layer = packet->getPrevLayerOfType<pcpp::IPv4Layer>(tcpLayer);
        *this = FlowId(ipv4Layer, tcpLayer);
    } else {
        auto* udpLayer = packet->getLayerOfType<pcpp::UdpLayer>();
        auto* ipv4Layer = packet->getPrevLayerOfType<pcpp::IPv4Layer>(udpLayer);
        *this = FlowId(ipv4Layer, udpLayer);
    }
}

FlowId::FlowId(uint16_t pktPorts[2], IPv4 pktIps[2])
{
    direction = FROM_CLIENT;
    if (pktPorts[0] < pktPorts[1]) {
        direction = FROM_SERVER;
}
    ips[0] = pktIps[0 + direction];
    ips[1] = pktIps[1 - direction];
    ports[0] = pktPorts[0 + direction];
    ports[1] = pktPorts[1 - direction];
}
}  // namespace flowstats
