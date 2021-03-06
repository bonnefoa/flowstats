#include "Collector.hpp"
#include "DnsStatsCollector.hpp"
#include "MainTest.hpp"
#include "TcpStatsCollector.hpp"
#include "Utils.hpp"
#include <catch2/catch.hpp>

using namespace flowstats;

TEST_CASE("Tcp simple", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("Tcp aggregated stats are computed")
    {
        tester.readPcap("tcp_simple.pcap", "port 53");
        tester.readPcap("tcp_simple.pcap", "port 80", false);

        auto tcpKey = AggregatedKey("google.com", {}, 80);
        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        auto it = aggregatedMap.find(tcpKey);
        REQUIRE(it != aggregatedMap.end());

        auto const* aggregatedFlow = it->second;

        CHECK(aggregatedFlow->getFieldStr(Field::SYN, FROM_CLIENT, 1, 0) == "1");
        CHECK(aggregatedFlow->getFieldStr(Field::FIN, FROM_CLIENT, 1, 0) == "1");
        CHECK(aggregatedFlow->getFieldStr(Field::CLOSE, FROM_CLIENT, 1, 0) == "1");
        CHECK(aggregatedFlow->getFieldStr(Field::ACTIVE_CONNECTIONS, FROM_CLIENT, 1, 0) == "0");
        CHECK(aggregatedFlow->getFieldStr(Field::CONN, FROM_CLIENT, 1, 0) == "1");
        CHECK(aggregatedFlow->getFieldStr(Field::CONN_RATE, FROM_CLIENT, 1, 0) == "1");
        CHECK(aggregatedFlow->getFieldStr(Field::CT_P99, FROM_CLIENT, 1, 0) == "50ms");
        CHECK(aggregatedFlow->getFieldStr(Field::MTU, FROM_CLIENT, 1, 0) == "140");
        CHECK(aggregatedFlow->getFieldStr(Field::MTU, FROM_SERVER, 1, 0) == "594");

        auto flows = tcpStatsCollector.getTcpFlow();
        CHECK(flows.size() == 1);
        CHECK(flows.begin()->second.getGap() == 0);

        AggregatedKey totalKey = AggregatedKey("Total", {}, 0);
        std::map<Field, std::string> totalValues;
        CHECK(aggregatedFlow->getFieldStr(Field::SYN, FROM_CLIENT, 1, 0) == "1");
    }
}

TEST_CASE("Tcp sort", "[tcp]")
{
    auto tester = Tester();
    auto& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("Fqdn sort works")
    {
        tester.readPcap("testcom.pcap");
        auto& ipToFqdn = tester.getIpToFqdn();
        REQUIRE(ipToFqdn.getFlowFqdn(IPAddress(Tins::IPv4Address("35.155.52.1"))) == "Unknown");
        auto const*aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap->size() == 4);

        auto flows = tcpStatsCollector.getAggregatedFlows();
        CHECK(flows[0]->getFqdn() == "news.ycombinator.com");
        CHECK(flows[1]->getFqdn() == "Unknown");
        CHECK(flows[2]->getFqdn() == "www.test.com");
        CHECK(flows[3]->getFqdn() == "www.test.com");

        tcpStatsCollector.setSortField(Field::FQDN, true);
        flows = tcpStatsCollector.getAggregatedFlows();
        CHECK(flows[0]->getFqdn() == "www.test.com");
        CHECK(flows[1]->getFqdn() == "www.test.com");
        CHECK(flows[2]->getFqdn() == "Unknown");
        CHECK(flows[3]->getFqdn() == "news.ycombinator.com");

        tcpStatsCollector.setSortField(Field::PORT, false);
        flows = tcpStatsCollector.getAggregatedFlows();
        CHECK(flows[0]->getSrvPort() == 80);
        CHECK(flows[1]->getSrvPort() == 443);
        CHECK(flows[2]->getSrvPort() == 443);
        CHECK(flows[3]->getSrvPort() == 443);
    }
}

TEST_CASE("https pcap", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("Active connections are correctly counted")
    {
        auto tcpKey = AggregatedKey("Unknown", {}, 443);
        tester.readPcap("https.pcap", "port 443", false);

        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        auto const* aggregatedFlow = aggregatedMap[tcpKey];

        CHECK(aggregatedFlow->getFieldStr(Field::SYN, FROM_CLIENT, 1, 0)== "1");
        CHECK(aggregatedFlow->getFieldStr(Field::FIN, FROM_CLIENT, 1, 0)== "1");
        CHECK(aggregatedFlow->getFieldStr(Field::CLOSE, FROM_CLIENT, 1, 0)== "1");
        CHECK(aggregatedFlow->getFieldStr(Field::ACTIVE_CONNECTIONS, FROM_CLIENT, 1, 0)== "0");
        CHECK(aggregatedFlow->getFieldStr(Field::CONN, FROM_CLIENT, 1, 0)== "1");
        CHECK(aggregatedFlow->getFieldStr(Field::CT_P99, FROM_CLIENT, 1, 0)== "1ms");

        auto flows = tcpStatsCollector.getTcpFlow();
        REQUIRE(flows.size() == 1);
        CHECK(flows.begin()->second.getGap() == 0);
    }
}

TEST_CASE("Tcp gap connection", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("Connection time is not computed if there's a gap ")
    {
        tester.readPcap("connection_with_gap.pcap");

        auto tcpKey = AggregatedKey("Unknown", {}, 443);
        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        auto *aggregatedFlow = aggregatedMap[tcpKey];

        CHECK(aggregatedFlow->getFieldStr(Field::CONN, FROM_CLIENT, 1, 0)== "0");
    }
}

TEST_CASE("Tcp reused port", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();
    SECTION("Reused connections")
    {
        tester.readPcap("reuse_port.pcap");

        auto tcpKey = AggregatedKey("Unknown", {}, 1234);
        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        auto *aggregatedFlow = aggregatedMap[tcpKey];

        CHECK(aggregatedFlow->getFieldStr(Field::SYN, FROM_CLIENT, 1, 0) == "6");
        CHECK(aggregatedFlow->getFieldStr(Field::FIN, FROM_CLIENT, 1, 0) == "5");
        CHECK(aggregatedFlow->getFieldStr(Field::CLOSE, FROM_CLIENT, 1, 0) == "5");
        CHECK(aggregatedFlow->getFieldStr(Field::ACTIVE_CONNECTIONS, FROM_CLIENT, 1, 0) == "0");
        CHECK(aggregatedFlow->getFieldStr(Field::CONN, FROM_CLIENT, 1, 0) == "5");
        CHECK(aggregatedFlow->getFieldStr(Field::CT_P99, FROM_CLIENT, 1, 0) == "0ms");
        CHECK(aggregatedFlow->getFieldStr(Field::SRT_P99, FROM_CLIENT, 1, 0) == "0ms");

        auto flows = tcpStatsCollector.getTcpFlow();
        REQUIRE(flows.size() == 0);
    }
}

TEST_CASE("Ssl stream ack + srt", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();
    SECTION("Only payload from client starts SRT")
    {
        auto tcpKey = AggregatedKey("Unknown", {}, 443);
        tester.readPcap("ssl_ack_srt.pcap");

        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        auto const* aggregatedFlow = aggregatedMap[tcpKey];

        REQUIRE(aggregatedFlow->getFieldStr(Field::SRT, FROM_CLIENT, 1, 0) == "2");
        REQUIRE(aggregatedFlow->getFieldStr(Field::SRT_P99, FROM_CLIENT, 1, 0) == "2ms");
        REQUIRE(aggregatedFlow->getFieldStr(Field::SRT_P95, FROM_CLIENT, 1, 0) == "2ms");
    }
}

TEST_CASE("Ssl stream multiple srts", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();
    SECTION("Srts are correctly computed from single flow")
    {
        auto tcpKey = AggregatedKey("Unknown", {}, 443);
        tester.readPcap("tls_stream_extract.pcap");

        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        auto const* aggregatedFlow = aggregatedMap[tcpKey];

        REQUIRE(aggregatedFlow->getFieldStr(Field::SRT, FROM_CLIENT, 1, 0) == "11");
        REQUIRE(aggregatedFlow->getFieldStr(Field::SRT_P99, FROM_CLIENT, 1, 0) == "9ms");
        REQUIRE(aggregatedFlow->getFieldStr(Field::SRT_P95, FROM_CLIENT, 1, 0) == "3ms");
    }
}

TEST_CASE("Tcp double", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("Srts are correctly computed from multiple flows")
    {
        auto tcpKey = AggregatedKey("Unknown", {}, 3834);
        tester.readPcap("tcp_double.pcap");

        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);
        auto const* aggregatedFlow = aggregatedMap[tcpKey];

        CHECK(aggregatedFlow->getFieldStr(Field::SRT, FROM_CLIENT, 1, 0) == "2");
        CHECK(aggregatedFlow->getFieldStr(Field::SRT_P99, FROM_CLIENT, 1, 0) == "499ms");
        CHECK(aggregatedFlow->getFieldStr(Field::SRT_P95, FROM_CLIENT, 1, 0) == "499ms");
    }
}

TEST_CASE("Tcp 0 win", "[tcp]")
{
    auto tester = Tester(true);
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("0 wins are correctly counted")
    {
        tester.readPcap("0_win.pcap", "");

        auto ipFlows = tcpStatsCollector.getAggregatedMap();
        REQUIRE(ipFlows.size() == 1);

        auto tcpKey = AggregatedKey("Unknown",
                IPAddress(Tins::IPv4Address("127.0.0.1")), 443);
        auto const* flow = ipFlows[tcpKey];
        REQUIRE(flow != nullptr);

        CHECK(flow->getFieldStr(Field::ZWIN, FROM_SERVER, 1, 0) == "3");
        CHECK(flow->getFieldStr(Field::RST, FROM_SERVER, 1, 0) == "1");
    }
}

TEST_CASE("Tcp rst", "[tcp]")
{

    auto tester = Tester(true);
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();

    auto& ipToFqdn = tester.getIpToFqdn();
    Tins::IPv4Address ip("10.142.226.42");
    ipToFqdn.updateFqdn("whatever", { ip }, {});

    SECTION("Rst only close once")
    {
        tester.readPcap("rst_close.pcap", "");

        auto ipFlows = tcpStatsCollector.getAggregatedMap();
        REQUIRE(ipFlows.size() == 1);

        auto tcpKey = AggregatedKey("whatever", IPAddress(ip), 3834);
        auto const* flow = ipFlows[tcpKey];

        CHECK(flow->getFieldStr(Field::RST, FROM_CLIENT, 1, 0) == "2");
        CHECK(flow->getFieldStr(Field::CLOSE, FROM_CLIENT, 1, 0) == "1");
    }
}

TEST_CASE("Inversed srt", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("We correctly detect the server")
    {
        auto tcpKey = AggregatedKey("Unknown", {}, 9000);
        tester.readPcap("inversed_srv.pcap", "");

        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        auto const* aggregatedFlow = aggregatedMap[tcpKey];
        REQUIRE(aggregatedFlow != NULL);
        REQUIRE(aggregatedFlow->getSrvIp().getAddrStr() == "10.8.109.46");
    }
}

TEST_CASE("Request size", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("We correctly detect the server")
    {
        auto tcpKey = AggregatedKey("Unknown", {}, 9000);
        tester.readPcap("6_sec_srt_extract.pcap", "");

        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        auto const* flow = aggregatedMap[tcpKey];
        REQUIRE(flow != nullptr);

        REQUIRE(flow->getFieldStr(Field::DS_MAX, FROM_CLIENT, 1, 0) == "183 KB");
    }
}

TEST_CASE("Srv port detection", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("We correctly detect srv port")
    {
        auto tcpKey = AggregatedKey("Unknown", {}, 9000);
        tester.readPcap("port_detection.pcap", "", false);

        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        auto const* flow = aggregatedMap[tcpKey];
        REQUIRE(flow != nullptr);

        REQUIRE(flow->getFieldStr(Field::ACTIVE_CONNECTIONS, FROM_CLIENT, 1, 0) == "3");
    }
}

TEST_CASE("Gap in capture", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();

    SECTION("We don't compute SRT on gap")
    {
        auto tcpKey = AggregatedKey("Unknown", {}, 80);
        tester.readPcap("tcp_gap.pcap", "", false);

        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        auto const* flow = aggregatedMap[tcpKey];
        REQUIRE(flow != nullptr);

        CHECK(flow->getFieldStr(Field::SRT, FROM_CLIENT, 1, 0) == "1");
        CHECK(flow->getFieldStr(Field::SRT_P99, FROM_CLIENT, 1, 0) == "26ms");

        auto flows = tcpStatsCollector.getTcpFlow();
        CHECK(flows.size() == 1);
        CHECK(flows.begin()->second.getGap() == 1);
    }
}

TEST_CASE("Mtu is correctly computed", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();
    tester.readPcap("tcp_mtu.pcap", "");

    SECTION("We correctly compute mtu")
    {
        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        auto tcpKey = AggregatedKey("Unknown", {}, 80);
        auto const* flow = aggregatedMap[tcpKey];
        REQUIRE(flow != nullptr);

        CHECK(flow->getFieldStr(Field::MTU, FROM_CLIENT, 1, 0) == "15346");
        CHECK(flow->getFieldStr(Field::MTU, FROM_SERVER, 1, 0) == "413");
    }
}

TEST_CASE("Ipv6", "[tcp]")
{
    auto tester = Tester();
    auto const& tcpStatsCollector = tester.getTcpStatsCollector();
    auto const& dnsStatsCollector = tester.getDnsStatsCollector();
    tester.readPcap("ipv6.pcap", "");

    SECTION("We build ipv6 to fqdn mapping")
    {
        auto aggregatedMap = dnsStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 2);
        auto dnsKey = AggregatedKey::aggregatedDnsKey("google.fr",
            Tins::DNS::AAAA, Transport::UDP);
        auto const* flow = aggregatedMap[dnsKey];
        REQUIRE(flow != nullptr);
    }

    SECTION("We correctly compute ipv6 tcp traffic")
    {
        auto aggregatedMap = tcpStatsCollector.getAggregatedMap();
        REQUIRE(aggregatedMap.size() == 1);

        auto tcpKey = AggregatedKey("google.fr", {}, 80);
        auto const* flow = aggregatedMap[tcpKey];
        REQUIRE(flow != nullptr);

        CHECK(flow->getFieldStr(Field::BYTES, FROM_CLIENT, 1, 0) == "609 B");
        CHECK(flow->getFieldStr(Field::BYTES, FROM_SERVER, 1, 0) == "886 B");
    }
}
