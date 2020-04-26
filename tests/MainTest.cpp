#define CATCH_CONFIG_MAIN
#include "MainTest.hpp"
#include "PktSource.hpp"
#include <catch2/catch.hpp>
#include <spdlog/spdlog.h>
#include <sys/stat.h>

using namespace flowstats;

Tester::Tester()
    : conf()
    , dnsStatsCollector(conf, displayConf)
    , sslStatsCollector(conf, displayConf)
    , tcpStatsCollector(conf, displayConf)
{
    conf.displayUnknownFqdn = true;
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
        for (auto collector : collectors) {
            try {
                collector->processPacket(packet);
            } catch (const payload_too_small&) {
            } catch (const Tins::malformed_packet&) {
            } catch (const Tins::pdu_not_found&) {
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
