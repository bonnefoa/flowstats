#include "Collector.hpp"
#include "DnsStatsCollector.hpp"
#include "MainTest.hpp"
#include <catch2/catch.hpp>

using namespace flowstats;

TEST_CASE("Dns queries timeout", "[dns]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& dnsStatsCollector = tester.getDnsStatsCollector();

    tester.readPcap("dns_simple.pcap");

    auto aggregatedFlows = dnsStatsCollector.getAggregatedMap();
    REQUIRE(aggregatedFlows->size() == 3);

    auto firstKey = AggregatedKey::aggregatedDnsKey("test.com", Tins::DNS::A, Transport::UDP);
    auto firstFlow = aggregatedFlows->at(firstKey);
    std::map<Field, std::string> cltValues;
    CHECK(firstFlow->getFieldStr(Field::REQ, FROM_CLIENT, 1, 0) == "1");
    CHECK(firstFlow->getFieldStr(Field::TIMEOUTS, FROM_CLIENT, 1, 0) == "0");

    auto thirdKey = AggregatedKey::aggregatedDnsKey("google.com", Tins::DNS::A, Transport::UDP);
    auto thirdFlow = aggregatedFlows->at(thirdKey);
    CHECK(thirdFlow->getFieldStr(Field::REQ, FROM_CLIENT, 1, 0) == "1");
    CHECK(thirdFlow->getFieldStr(Field::TIMEOUTS, FROM_CLIENT, 1, 0) == "1");
}

TEST_CASE("Dns rcrd/rsps", "[dns]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& dnsStatsCollector = tester.getDnsStatsCollector();
    tester.readPcap("dns_rcrds.pcap");

    auto aggregatedFlows = dnsStatsCollector.getAggregatedMap();
    REQUIRE(aggregatedFlows->size() == 1);

    auto udpKey = AggregatedKey::aggregatedDnsKey("all.alb-metrics-agent-shard1-770518637.us-east-1.elb.amazonaws.com",
        Tins::DNS::A, Transport::UDP);
    auto firstFlow = aggregatedFlows->at(udpKey);
    std::map<Field, std::string> cltValues;
    CHECK(firstFlow->getFieldStr(Field::REQ, FROM_CLIENT, 1, 0) == "1");
    CHECK(firstFlow->getFieldStr(Field::RR_A_AVG, FROM_CLIENT, 1, 0) == "48");
    CHECK(firstFlow->getFieldStr(Field::RR_OTHER_AVG, FROM_CLIENT, 1, 0) == "0");
}

TEST_CASE("Dns tcp", "[dns]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& dnsStatsCollector = tester.getDnsStatsCollector();
    tester.readPcap("dns_tcp.pcap");

    auto aggregatedFlows = dnsStatsCollector.getAggregatedMap();
    REQUIRE(aggregatedFlows->size() == 1);

}
