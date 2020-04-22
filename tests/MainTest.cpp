#define CATCH_CONFIG_MAIN
#include "PktSource.hpp"
#include <catch2/catch.hpp>
#include <spdlog/spdlog.h>
#include <sys/stat.h>

using namespace flowstats;

int readPcap(std::string pcap, Collector& collector, std::string filter = "",
    bool advanceTick = true)
{
    struct stat buffer;
    std::string fullPath = fmt::format("{}/pcaps/{}", TEST_PATH, pcap);
    INFO("Checking file " << fullPath);
    REQUIRE(stat(fullPath.c_str(), &buffer) == 0);

    Tins::FileSniffer* reader = getPcapReader(fullPath, filter);

    int i = 0;
    while (true) {
        Tins::PtrPacket packet = reader->next_packet();
        if (packet.timestamp().seconds() == 0) {
            break;
        }
        i++;
        collector.processPacket(packet);
    }
    spdlog::info("Processed {} packets", i);

    if (advanceTick) {
        collector.advanceTick(maxTimeval);
    }
    delete reader;
    return 0;
}
