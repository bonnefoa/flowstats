#define CATCH_CONFIG_MAIN
#include "MainTest.hpp"
#include "PktSource.hpp"
#include <catch2/catch.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
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
    pktSource = new PktSource(nullptr, conf, collectors, &shouldStop);
}

auto Tester::readPcap(std::string const& pcap, std::string const& bpf, bool advanceTick) -> int
{
    struct stat buffer = {};
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
        pktSource->processPacketSource(packet);
    }
    SPDLOG_INFO("Processed {} packets", i);

    if (advanceTick) {
        for (auto *collector : collectors) {
            collector->advanceTick(maxTimeval);
        }
    }
    return 0;
}
