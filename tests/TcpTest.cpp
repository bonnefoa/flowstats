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

        std::map<Field, std::string> cltValues;
        aggregatedFlow->fillValues(cltValues, FROM_CLIENT, 0);
        std::map<Field, std::string> srvValues;
        aggregatedFlow->fillValues(srvValues, FROM_SERVER, 0);

        CHECK(cltValues[Field::SYN] == "1");
        CHECK(cltValues[Field::FIN] == "1");
        CHECK(cltValues[Field::CLOSE] == "1");
        CHECK(cltValues[Field::ACTIVE_CONNECTIONS] == "0");
        CHECK(cltValues[Field::CONN] == "1");
        CHECK(cltValues[Field::CT_P99] == "50ms");
        CHECK(cltValues[Field::MTU] == "140");
        CHECK(srvValues[Field::MTU] == "594");

        auto flows = tcpStatsCollector.getTcpFlow();
        CHECK(flows.size() == 1);
        CHECK(flows[0].getGap() == 0);
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

        std::map<Field, std::string> cltValues;
        aggregatedFlow->fillValues(cltValues, FROM_CLIENT, 0);

        CHECK(cltValues[Field::SYN] == "1");
        CHECK(cltValues[Field::FIN] == "1");
        CHECK(cltValues[Field::CLOSE] == "1");
        CHECK(cltValues[Field::ACTIVE_CONNECTIONS] == "0");
        CHECK(cltValues[Field::CONN] == "1");
        CHECK(cltValues[Field::CT_P99] == "1ms");

        auto flows = tcpStatsCollector.getTcpFlow();
        REQUIRE(flows.size() == 1);
        CHECK(flows[0].getGap() == 0);
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

        std::map<Field, std::string> cltValues;
        aggregatedFlow->fillValues(cltValues, FROM_CLIENT, 0);

        CHECK(cltValues[Field::SYN] == "6");
        CHECK(cltValues[Field::FIN] == "5");
        CHECK(cltValues[Field::CLOSE] == "5");
        CHECK(cltValues[Field::ACTIVE_CONNECTIONS] == "0");
        CHECK(cltValues[Field::CONN] == "5");
        CHECK(cltValues[Field::CT_P99] == "0ms");
        CHECK(cltValues[Field::SRT_P99] == "0ms");

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

        std::map<Field, std::string> cltValues;
        aggregatedFlow->fillValues(cltValues, FROM_CLIENT, 0);

        REQUIRE(cltValues[Field::SRT] == "2");
        REQUIRE(cltValues[Field::SRT_P99] == "2ms");
        REQUIRE(cltValues[Field::SRT_P95] == "2ms");
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

        std::map<Field, std::string> cltValues;
        aggregatedFlow->fillValues(cltValues, FROM_CLIENT, 0);

        REQUIRE(cltValues[Field::SRT] == "11");
        REQUIRE(cltValues[Field::SRT_P99] == "9ms");
        REQUIRE(cltValues[Field::SRT_P95] == "3ms");
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

        std::map<Field, std::string> cltValues;
        aggregatedFlow->fillValues(cltValues, FROM_CLIENT, 0);

        CHECK(cltValues[Field::SRT] == "2");
        CHECK(cltValues[Field::SRT_P99] == "499ms");
        CHECK(cltValues[Field::SRT_P95] == "499ms");
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

        std::map<Field, std::string> srvValues;
        flow->fillValues(srvValues, FROM_SERVER, 0);
        REQUIRE(flow != nullptr);

        CHECK(srvValues[Field::ZWIN] == "3");
        CHECK(srvValues[Field::RST] == "1");
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

        std::map<Field, std::string> cltValues;
        flow->fillValues(cltValues, FROM_CLIENT, 0);

        CHECK(cltValues[Field::RST] == "2");
        CHECK(cltValues[Field::CLOSE] == "1");
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

        auto flow = aggregatedMap[tcpKey];
        REQUIRE(flow != nullptr);

        std::map<Field, std::string> cltValues;
        flow->fillValues(cltValues, FROM_CLIENT, 0);

        REQUIRE(cltValues[Field::DSMAX] == "183.5 KB");
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

        auto flow = aggregatedMap[tcpKey];
        REQUIRE(flow != nullptr);

        std::map<Field, std::string> cltValues;
        flow->fillValues(cltValues, FROM_CLIENT, 0);

        REQUIRE(cltValues[Field::ACTIVE_CONNECTIONS] == "3");
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

        auto flow = aggregatedMap[tcpKey];
        REQUIRE(flow != nullptr);

        std::map<Field, std::string> cltValues;
        flow->fillValues(cltValues, FROM_CLIENT, 0);

        CHECK(cltValues[Field::SRT] == "1");
        CHECK(cltValues[Field::SRT_P99] == "26ms");

        auto flows = tcpStatsCollector.getTcpFlow();
        CHECK(flows.size() == 1);
        CHECK(flows[0].getGap() == 0);
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

        auto tcpKey = AggregatedTcpKey("Unknown", 0, 80);
        auto flow = aggregatedMap[tcpKey];
        REQUIRE(flow != nullptr);

        std::map<Field, std::string> cltValues;
        flow->fillValues(cltValues, FROM_CLIENT, 0);
        std::map<Field, std::string> srvValues;
        flow->fillValues(srvValues, FROM_SERVER, 0);

        CHECK(cltValues[Field::MTU] == "15346");
        CHECK(srvValues[Field::MTU] == "413");
    }
}
