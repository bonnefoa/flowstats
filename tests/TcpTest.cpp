#include "Collector.hpp"
#include "DnsStatsCollector.hpp"
#include "MainTest.hpp"
#include "TcpStatsCollector.hpp"
#include "Utils.hpp"
#include <catch2/catch.hpp>
#include <spdlog/spdlog.h>

using namespace flowstats;

TEST_CASE("Tcp simple", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("Tcp aggregated stats are computed")
    {
        tester.readPcap("tcp_simple.pcap", "port 53");
        tester.readPcap("tcp_simple.pcap", "port 80", false);

        AggregatedTcpKey tcpKey = AggregatedTcpKey("google.com", 0, 80);
        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        CHECK(aggregatedFlow->syns[0] == 1);
        CHECK(aggregatedFlow->fins[0] == 1);
        CHECK(aggregatedFlow->totalCloses == 1);
        CHECK(aggregatedFlow->activeConnections == 0);
        CHECK(aggregatedFlow->connections.getCount() == 1);
        CHECK(aggregatedFlow->connections.getPercentile(1.0) == 50);
        CHECK(aggregatedFlow->srts.getPercentile(1.0) == 81);
        CHECK(aggregatedFlow->mtu[0] == 140);
        CHECK(aggregatedFlow->mtu[1] == 594);

        auto flows = tcpStatsCollector.getTcpFlow();
        CHECK(flows.size() == 1);
        CHECK(flows[0].gap == 0);
    }
}

TEST_CASE("https pcap", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("Active connections are correctly counted")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 443);
        tester.readPcap("https.pcap", "port 443", false);

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        CHECK(aggregatedFlow->syns[0] == 1);
        CHECK(aggregatedFlow->fins[0] == 1);
        CHECK(aggregatedFlow->totalCloses == 1);
        CHECK(aggregatedFlow->activeConnections == 0);
        CHECK(aggregatedFlow->connections.getCount() == 1);
        CHECK(aggregatedFlow->connections.getPercentile(1.0) == 1);

        auto flows = tcpStatsCollector.getTcpFlow();
        REQUIRE(flows.size() == 1);
        CHECK(flows[0].gap == 0);
    }
}

TEST_CASE("Tcp reused port", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();
    SECTION("Reused connections")
    {
        tester.readPcap("reuse_port.pcap");

        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 1234);
        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow->syns[0] == 6);
        REQUIRE(aggregatedFlow->fins[0] == 5);
        REQUIRE(aggregatedFlow->totalCloses == 5);
        REQUIRE(aggregatedFlow->activeConnections == 0);
        REQUIRE(aggregatedFlow->connections.getCount() == 5);
        REQUIRE(aggregatedFlow->connections.getPercentile(1.0) == 0);
        REQUIRE(aggregatedFlow->srts.getPercentile(1.0) == 0);

        auto flows = tcpStatsCollector.getTcpFlow();
        REQUIRE(flows.size() == 0);
    }
}

TEST_CASE("Ssl stream ack + srt", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();
    SECTION("Only payload from client starts SRT")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 443);
        tester.readPcap("ssl_ack_srt.pcap");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow->totalSrts == 2);
        aggregatedFlow->srts.merge();
        REQUIRE(aggregatedFlow->srts.getPercentile(1.0) == 2);
        REQUIRE(aggregatedFlow->srts.getPercentile(0) == 2);
    }
}

TEST_CASE("Ssl stream multiple srts", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();
    SECTION("Srts are correctly computed from single flow")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 443);
        tester.readPcap("tls_stream_extract.pcap");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow->totalSrts == 11);
        aggregatedFlow->srts.merge();
        REQUIRE(aggregatedFlow->srts.getPercentile(1.0) == 9);
        REQUIRE(aggregatedFlow->srts.getPercentile(0.95) == 5);
        REQUIRE(aggregatedFlow->srts.getPercentile(0) == 2);
    }
}

TEST_CASE("Tcp double", "[tcp]")
{
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("Srts are correctly computed from multiple flows")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 3834);
        tester.readPcap("tcp_double.pcap");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow->srts.getCount() == 2);
        REQUIRE(aggregatedFlow->srts.getPercentile(1.0) == 499);
        REQUIRE(aggregatedFlow->srts.getPercentile(0.5) == 79);
    }
}

TEST_CASE("Tcp 0 win", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester(true);
    auto& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("0 wins are correctly counted")
    {
        tester.readPcap("0_win.pcap", "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> ipFlows = tcpStatsCollector.getAggregatedMap();
        REQUIRE(ipFlows.size() == 1);

        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", Tins::IPv4Address("127.0.0.1"), 443);
        auto flow = ipFlows[tcpKey];
        REQUIRE(flow->zeroWins[FROM_SERVER] == 3);
        REQUIRE(flow->rsts[FROM_SERVER] == 1);
    }
}

TEST_CASE("Tcp rst", "[tcp]")
{

    auto tester = Tester(true);
    auto& tcpStatsCollector = tester.getTcpStatsCollector();

    auto& ipToFqdn = tester.getIpToFqdn();
    Tins::IPv4Address ip("10.142.226.42");
    ipToFqdn.updateFqdn("whatever", ip);

    SECTION("Rst only close once")
    {
        tester.readPcap("rst_close.pcap", "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> ipFlows = tcpStatsCollector.getAggregatedMap();
        REQUIRE(ipFlows.size() == 1);

        AggregatedTcpKey tcpKey = AggregatedTcpKey("whatever", ip, 3834);
        auto flow = ipFlows[tcpKey];
        REQUIRE(flow->rsts[FROM_CLIENT] == 2);
        REQUIRE(flow->closes == 1);
    }
}

TEST_CASE("Inversed srt", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("We correctly detect the server")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 9000);
        tester.readPcap("inversed_srv.pcap", "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        REQUIRE(aggregatedFlow->getSrvIp() == "10.8.109.46");
    }
}

TEST_CASE("Request size", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("We correctly detect the server")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 9000);
        tester.readPcap("6_sec_srt_extract.pcap", "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        REQUIRE(aggregatedFlow->requestSizes.getPercentile(1.0) == 187910);
    }
}

TEST_CASE("Srv port detection", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("We correctly detect srv port")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 9000);
        tester.readPcap("port_detection.pcap", "", false);

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        REQUIRE(aggregatedFlow->activeConnections == 3);
    }
}

TEST_CASE("Gap in capture", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("We don't compute SRT on gap")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 80);
        tester.readPcap("tcp_gap.pcap", "", false);

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        REQUIRE(aggregatedFlow->totalSrts == 1);
        REQUIRE(aggregatedFlow->srts.getPercentile(1.0) == 26);

        auto flows = tcpStatsCollector.getTcpFlow();
        CHECK(flows.size() == 1);
        CHECK(flows[0].gap == 0);
    }
}

TEST_CASE("Mtu is correctly computed", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();
    tester.readPcap("tcp_mtu.pcap", "");

    SECTION("We correctly compute mtu")
    {
        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 80);
        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        CHECK(aggregatedFlow->mtu[FROM_CLIENT] == 15346);
        CHECK(aggregatedFlow->mtu[FROM_SERVER] == 413);
    }
}
