#include "Collector.hpp"
#include "DnsStatsCollector.hpp"
#include "MainTest.hpp"
#include "TcpStatsCollector.hpp"
#include "Utils.hpp"
#include <catch2/catch.hpp>
#include <spdlog/spdlog.h>

using namespace flowstats;

FlowstatsConfiguration conf;
DisplayConfiguration displayConf;
TcpStatsCollector getTcpStatsCollector()
{
    conf.displayUnknownFqdn = true;
    return TcpStatsCollector(conf, displayConf);
}

TEST_CASE("Tcp simple", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);

    SECTION("Tcp aggregated stats are computed")
    {
        FlowstatsConfiguration conf;
        DnsStatsCollector dnsStats(conf, displayConf);
        readPcap("tcp_simple.pcap", dnsStats, "port 53");

        AggregatedTcpKey tcpKey = AggregatedTcpKey("google.com", 0, 80);

        TcpStatsCollector tcpCollector(conf, displayConf);
        readPcap("tcp_simple.pcap", tcpCollector, "port 80", false);

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
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

        std::map<uint32_t, TcpFlow> flows = tcpCollector.getTcpFlow();
        CHECK(flows.size() == 1);
        CHECK(flows[0].gap == 0);
    }
}

TEST_CASE("https pcap", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);

    SECTION("Active connections are correctly counted")
    {
        FlowstatsConfiguration conf;
        conf.displayUnknownFqdn = true;
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 443);

        TcpStatsCollector tcpCollector(conf, displayConf);
        readPcap("https.pcap", tcpCollector, "port 443", false);

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        CHECK(aggregatedFlow->syns[0] == 1);
        CHECK(aggregatedFlow->fins[0] == 1);
        CHECK(aggregatedFlow->totalCloses == 1);
        CHECK(aggregatedFlow->activeConnections == 0);
        CHECK(aggregatedFlow->connections.getCount() == 1);
        CHECK(aggregatedFlow->connections.getPercentile(1.0) == 1);

        std::map<uint32_t, TcpFlow> flows = tcpCollector.getTcpFlow();
        REQUIRE(flows.size() == 1);
        CHECK(flows[0].gap == 0);
    }
}

TEST_CASE("Tcp reused port", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);

    SECTION("Reused connections")
    {
        TcpStatsCollector tcpCollector = getTcpStatsCollector();
        readPcap("reuse_port.pcap", tcpCollector, "");

        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 1234);
        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow->syns[0] == 6);
        REQUIRE(aggregatedFlow->fins[0] == 5);
        REQUIRE(aggregatedFlow->totalCloses == 5);
        REQUIRE(aggregatedFlow->activeConnections == 0);
        REQUIRE(aggregatedFlow->connections.getCount() == 5);
        REQUIRE(aggregatedFlow->connections.getPercentile(1.0) == 0);
        REQUIRE(aggregatedFlow->srts.getPercentile(1.0) == 0);

        std::map<uint32_t, TcpFlow> flows = tcpCollector.getTcpFlow();
        REQUIRE(flows.size() == 0);
    }
}

TEST_CASE("Ssl stream ack + srt", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);
    SECTION("Only payload from client starts SRT")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 443);

        TcpStatsCollector tcpCollector = getTcpStatsCollector();
        readPcap("ssl_ack_srt.pcap", tcpCollector, "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
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
    SECTION("Srts are correctly computed from single flow")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 443);

        auto tcpCollector = getTcpStatsCollector();
        readPcap("tls_stream_extract.pcap", tcpCollector, "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
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
    SECTION("Srts are correctly computed from multiple flows")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 3834);

        TcpStatsCollector tcpCollector = getTcpStatsCollector();
        readPcap("tcp_double.pcap", tcpCollector, "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
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

    SECTION("0 wins are correctly counted")
    {
        FlowstatsConfiguration conf;
        conf.displayUnknownFqdn = true;
        conf.perIpAggr = true;
        TcpStatsCollector tcpStatsIp(conf, displayConf);
        readPcap("0_win.pcap", tcpStatsIp, "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> ipFlows = tcpStatsIp.getAggregatedMap();
        REQUIRE(ipFlows.size() == 1);

        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", pcpp::IPv4Address("127.0.0.1").toInt(), 443);
        auto flow = ipFlows[tcpKey];
        REQUIRE(flow->zeroWins[FROM_SERVER] == 3);
        REQUIRE(flow->rsts[FROM_SERVER] == 1);
    }
}

TEST_CASE("Tcp rst", "[tcp]")
{
    FlowstatsConfiguration conf;
    pcpp::IPv4Address ip("10.142.226.42");
    conf.ipToFqdn[ip.toInt()] = "whatever";

    conf.perIpAggr = true;
    SECTION("Rst only close once")
    {
        TcpStatsCollector tcpStatsIp(conf, displayConf);
        readPcap("rst_close.pcap", tcpStatsIp, "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> ipFlows = tcpStatsIp.getAggregatedMap();
        REQUIRE(ipFlows.size() == 1);

        AggregatedTcpKey tcpKey = AggregatedTcpKey("whatever", ip.toInt(), 3834);
        auto flow = ipFlows[tcpKey];
        REQUIRE(flow->rsts[FROM_CLIENT] == 2);
        REQUIRE(flow->closes == 1);
    }
}

TEST_CASE("Inversed srt", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);

    SECTION("We correctly detect the server")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 9000);

        TcpStatsCollector tcpCollector = getTcpStatsCollector();
        readPcap("inversed_srv.pcap", tcpCollector, "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        REQUIRE(aggregatedFlow->getSrvIp().toString() == "10.8.109.46");
    }
}

TEST_CASE("Request size", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);

    SECTION("We correctly detect the server")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 9000);

        TcpStatsCollector tcpCollector = getTcpStatsCollector();
        readPcap("6_sec_srt_extract.pcap", tcpCollector, "");

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        REQUIRE(aggregatedFlow->requestSizes.getPercentile(1.0) == 187910);
    }
}

TEST_CASE("Srv port detection", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);

    SECTION("We correctly detect srv port")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 9000);

        TcpStatsCollector tcpCollector = getTcpStatsCollector();
        readPcap("port_detection.pcap", tcpCollector, "", false);

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        REQUIRE(aggregatedFlow->activeConnections == 3);
    }
}

TEST_CASE("Gap in capture", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);

    SECTION("We don't compute SRT on gap")
    {
        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 80);

        TcpStatsCollector tcpCollector = getTcpStatsCollector();
        readPcap("tcp_gap.pcap", tcpCollector, "", false);

        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        REQUIRE(aggregatedFlow->totalSrts == 1);
        REQUIRE(aggregatedFlow->srts.getPercentile(1.0) == 26);

        std::map<uint32_t, TcpFlow> flows = tcpCollector.getTcpFlow();
        CHECK(flows.size() == 1);
        CHECK(flows[0].gap == 0);
    }
}

TEST_CASE("Mtu is correctly computed", "[tcp]")
{
    spdlog::set_level(spdlog::level::debug);

    TcpStatsCollector tcpCollector = getTcpStatsCollector();
    readPcap("tcp_mtu.pcap", tcpCollector, "");

    SECTION("We correctly compute mtu")
    {
        std::map<AggregatedTcpKey, AggregatedTcpFlow*> aggregatedMap = tcpCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        AggregatedTcpKey tcpKey = AggregatedTcpKey("Unknown", 0, 80);
        AggregatedTcpFlow* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        CHECK(aggregatedFlow->mtu[FROM_CLIENT] == 15346);
        CHECK(aggregatedFlow->mtu[FROM_SERVER] == 413);
    }
}
