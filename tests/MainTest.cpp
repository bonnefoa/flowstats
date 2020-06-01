#define CATCH_CONFIG_MAIN
#include "MainTest.hpp"
#include "PktSource.hpp"
#include <catch2/catch.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sys/stat.h>

using namespace flowstats;

Tester::Tester(bool perIpAggr)
    : conf()
    , ipToFqdn(conf)
    , dnsStatsCollector(conf, displayConf, &ipToFqdn)
    , sslStatsCollector(conf, displayConf, &ipToFqdn)
    , tcpStatsCollector(conf, displayConf, &ipToFqdn)
{
    auto logger = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    spdlog::default_logger()->sinks().push_back(logger);

    spdlog::set_level(spdlog::level::debug);
    conf.setDisplayUnknownFqdn(true);
    conf.setPerIpAggr(perIpAggr);
    collectors.push_back(&dnsStatsCollector);
    collectors.push_back(&sslStatsCollector);
    collectors.push_back(&tcpStatsCollector);
}

auto Tester::readPcap(std::string pcap, std::string bpf, bool advanceTick) -> int
{
    struct stat buffer;
    std::string fullPath = fmt::format("{}/pcaps/{}", TEST_PATH, pcap);
    INFO("Checking file " << fullPath);
    REQUIRE(stat(fullPath.c_str(), &buffer) == 0);

    auto reader = Tins::FileSniffer(fullPath, bpf);

    int i = 0;
    while (true) {
        Tins::Packet packet = reader.next_packet();
        if (packet.timestamp().seconds() == 0) {
            break;
        }
        i++;

        auto const* pdu = packet.pdu();
        auto const* ip = pdu->find_pdu<Tins::IP>();
        auto const* ipv6 = pdu->find_pdu<Tins::IPv6>();
        if (ip == nullptr && ipv6 == nullptr) {
            continue;
        }
        Tins::PDU const* ipPdu = ip;
        if (ip == nullptr) {
            ipPdu = ipv6;
        }
        auto const* tcp = ipPdu->find_pdu<Tins::TCP>();
        Tins::UDP const* udp = nullptr;
        if (tcp == nullptr) {
            udp = ipPdu->find_pdu<Tins::UDP>();
        }

        auto flowId = FlowId(ip, ipv6, tcp, udp);
        for (auto collector : collectors) {
            try {
                collector->processPacket(packet, flowId, ip, ipv6, tcp, udp);
            } catch (Tins::malformed_packet const&) {
            }
        }
    }
    spdlog::info("Processed {} packets", i);

    if (advanceTick) {
        for (auto collector : collectors) {
            collector->advanceTick(maxTimeval);
        }
    }
    return 0;
}
