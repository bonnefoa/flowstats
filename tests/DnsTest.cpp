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

    auto collectorOutput = dnsStatsCollector.outputStatus(0);
    auto keys = collectorOutput.getKeyHeaders();
    CHECK(keys.find("Fqdn") == 0);

    auto aggregatedFlows = dnsStatsCollector.getAggregatedMap();
    REQUIRE(aggregatedFlows->size() == 3);

    AggregatedDnsKey firstKey("test.com", Tins::DNS::A, Transport::UDP);
    auto firstFlow = aggregatedFlows->at(firstKey);
    std::map<Field, std::string> cltValues;
    firstFlow->fillValues(cltValues, FROM_CLIENT);
    CHECK(cltValues[Field::REQ] == "1");
    CHECK(cltValues[Field::TIMEOUTS] == "0");

    AggregatedDnsKey thirdKey("google.com", Tins::DNS::A, Transport::UDP);
    auto thirdFlow = aggregatedFlows->at(thirdKey);
    thirdFlow->fillValues(cltValues, FROM_CLIENT);
    CHECK(cltValues[Field::REQ] == "1");
    CHECK(cltValues[Field::TIMEOUTS] == "1");
}

TEST_CASE("Dns rcrd/rsps", "[dns]")
{
    spdlog::set_level(spdlog::level::debug);
    auto tester = Tester();
    auto& dnsStatsCollector = tester.getDnsStatsCollector();
    tester.readPcap("dns_rcrds.pcap");

    auto aggregatedFlows = dnsStatsCollector.getAggregatedMap();
    REQUIRE(aggregatedFlows->size() == 1);

    AggregatedDnsKey udpKey("all.alb-metrics-agent-shard1-770518637.us-east-1.elb.amazonaws.com", Tins::DNS::A, Transport::UDP);
    auto firstFlow = aggregatedFlows->at(udpKey);
    std::map<Field, std::string> cltValues;
    firstFlow->fillValues(cltValues, FROM_CLIENT);
    CHECK(cltValues[Field::REQ] == "1");
    CHECK(cltValues[Field::RCRD_AVG] == "48");
}
