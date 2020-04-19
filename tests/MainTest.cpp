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

    pcpp::IFileReaderDevice* reader = getPcapReader(fullPath, filter);

    int i = 0;
    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        i++;
        pcpp::Packet parsedPacket(&rawPacket);
        collector.processPacket(&parsedPacket);
    }
    spdlog::info("Processed {} packets", i);

    if (advanceTick) {
        collector.advanceTick(maxTimeval);
    }
    delete reader;
    return 0;
}
