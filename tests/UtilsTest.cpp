#include "Utils.hpp"
#include "Collector.hpp"
#include "DnsStatsCollector.hpp"
#include "MainTest.hpp"
#include "TcpStatsCollector.hpp"
#include <catch2/catch.hpp>
#include <spdlog/spdlog.h>

using namespace flowstats;

TEST_CASE("Fqdn sort", "[sort]")
{
    auto flow1 = Flow("atest");
    auto flow2 = Flow("btes");
    auto flow3 = Flow("Ctests");
    auto flow4 = Flow("z1");
    auto flow5 = Flow("x9");
    std::vector<Flow const*> vec1 = { &flow5, &flow4, &flow2, &flow1, &flow3 };
    std::sort(vec1.begin(), vec1.end(), &Flow::sortByFqdn);
    CHECK(vec1[0]->getFqdn() == "atest");
    CHECK(vec1[1]->getFqdn() == "btes");
    CHECK(vec1[2]->getFqdn() == "Ctests");
    CHECK(vec1[3]->getFqdn() == "x9");
    CHECK(vec1[4]->getFqdn() == "z1");
}

