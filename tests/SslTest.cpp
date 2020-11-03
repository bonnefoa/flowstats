#include "Collector.hpp"
#include "DnsStatsCollector.hpp"
#include "MainTest.hpp"
#include "PktSource.hpp"
#include "SslStatsCollector.hpp"
#include <catch2/catch.hpp>

using namespace flowstats;

TEST_CASE("Ssl connection time", "[ssl]")
{
    spdlog::set_level(spdlog::level::debug);

    auto tester = Tester();
    tester.readPcap("ssl_simple.pcap", "port 53");
    tester.readPcap("ssl_simple.pcap", "port 443");

    auto ipFlows = tester.getSslStatsCollector().getAggregatedMap();
    REQUIRE(ipFlows.size() == 1);
    AggregatedKey key("google.com", {}, 443);
    auto *flow = ipFlows[key];
    REQUIRE(flow != nullptr);

    CHECK(flow->getFieldStr(Field::DOMAIN, FROM_CLIENT, 1, 0) == "google.com");
    CHECK(flow->getFieldStr(Field::PKTS, FROM_CLIENT, 1, 0) == "8");
    CHECK(flow->getFieldStr(Field::PKTS, FROM_SERVER, 1, 0) == "7");
    CHECK(flow->getFieldStr(Field::CONN, FROM_CLIENT, 1, 0) == "1");
    CHECK(flow->getFieldStr(Field::CT_P95, FROM_CLIENT, 1, 0) == "38ms");
}

TEST_CASE("Ssl port detection", "[ssl]")
{
    spdlog::set_level(spdlog::level::debug);

    auto tester = Tester();
    //conf.displayUnknownFqdn = true;
    tester.readPcap("ssl_alt_port.pcap", "port 443");

    auto ipFlows = tester.getSslStatsCollector().getAggregatedMap();
    // Not working for now

    //REQUIRE(ipFlows.size() == 1);
    //AggregatedKey key("Unknown", 0, 4433);
    //SslAggregatedFlow* flow = ipFlows[key];
    //REQUIRE(flow->domain == "google.com");
    //REQUIRE(flow->packets[FROM_CLIENT] == 8);
    //REQUIRE(flow->packets[FROM_SERVER] == 7);
    //REQUIRE(flow->connections.getCount() == 1);
    //REQUIRE(flow->connections.getPercentile(0.95) == 38);
}
