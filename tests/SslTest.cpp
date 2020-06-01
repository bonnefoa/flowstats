#include "Collector.hpp"
#include "DnsStatsCollector.hpp"
#include "MainTest.hpp"
#include "PktSource.hpp"
#include "SslStatsCollector.hpp"
#include <catch2/catch.hpp>
#include <spdlog/spdlog.h>

using namespace flowstats;

TEST_CASE("Ssl connection time", "[ssl]")
{
    spdlog::set_level(spdlog::level::debug);

    auto tester = Tester();
    tester.readPcap("ssl_simple.pcap", "port 53");
    tester.readPcap("ssl_simple.pcap", "port 443");

    auto ipFlows = tester.getSslStatsCollector().getAggregatedMap();
    REQUIRE(ipFlows.size() == 1);
    AggregatedKey key("google.com", 0, {}, 443);
    auto flow = ipFlows[key];
    REQUIRE(flow != nullptr);

    std::map<Field, std::string> cltValues;
    flow->fillValues(&cltValues, FROM_CLIENT);

    std::map<Field, std::string> srvValues;
    flow->fillValues(&srvValues, FROM_SERVER);

    CHECK(cltValues[Field::DOMAIN] == "google.com");
    CHECK(cltValues[Field::PKTS] == "8");
    CHECK(srvValues[Field::PKTS] == "7");
    CHECK(cltValues[Field::CONN] == "1");
    CHECK(cltValues[Field::CT_P95] == "38ms");
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
    //AggregatedSslFlow* flow = ipFlows[key];
    //REQUIRE(flow->domain == "google.com");
    //REQUIRE(flow->packets[FROM_CLIENT] == 8);
    //REQUIRE(flow->packets[FROM_SERVER] == 7);
    //REQUIRE(flow->connections.getCount() == 1);
    //REQUIRE(flow->connections.getPercentile(0.95) == 38);
}
