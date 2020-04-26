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

    std::map<AggregatedTcpKey, AggregatedSslFlow*> ipFlows = tester.getSslStatsCollector().getAggregatedMap();
    REQUIRE(ipFlows.size() == 1);
    AggregatedTcpKey key("google.com", 0, 443);
    AggregatedSslFlow* flow = ipFlows[key];
    //REQUIRE(flow->domain == "google.com");
    REQUIRE(flow->packets[FROM_CLIENT] == 8);
    REQUIRE(flow->packets[FROM_SERVER] == 7);
    REQUIRE(flow->connections.getCount() == 1);
    REQUIRE(flow->connections.getPercentile(0.95) == 38);
}

TEST_CASE("Ssl port detection", "[ssl]")
{
    spdlog::set_level(spdlog::level::debug);

    auto tester = Tester();
    //conf.displayUnknownFqdn = true;
    tester.readPcap("ssl_alt_port.pcap", "port 443");

    std::map<AggregatedTcpKey, AggregatedSslFlow*> ipFlows = tester.getSslStatsCollector().getAggregatedMap();
    // Not working for now

    //REQUIRE(ipFlows.size() == 1);
    //AggregatedTcpKey key("Unknown", 0, 4433);
    //AggregatedSslFlow* flow = ipFlows[key];
    //REQUIRE(flow->domain == "google.com");
    //REQUIRE(flow->packets[FROM_CLIENT] == 8);
    //REQUIRE(flow->packets[FROM_SERVER] == 7);
    //REQUIRE(flow->connections.getCount() == 1);
    //REQUIRE(flow->connections.getPercentile(0.95) == 38);
}
