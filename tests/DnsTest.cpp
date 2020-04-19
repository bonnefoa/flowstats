#include "Collector.hpp"
#include "DnsStatsCollector.hpp"
#include "MainTest.hpp"
#include <catch2/catch.hpp>

using namespace flowstats;

TEST_CASE("Dns queries timeout", "[dns]")
{
    spdlog::set_level(spdlog::level::debug);

    std::map<uint32_t, std::string> ipToFqdn;
    FlowstatsConfiguration conf;
    DisplayConfiguration displayConf;
    DnsStatsCollector dnsStats(conf, displayConf);

    readPcap("dns_simple.pcap", dnsStats);

    std::map<AggregatedDnsKey, AggregatedDnsFlow*> aggregatedFlows = dnsStats.getAggregatedFlow();
    REQUIRE(aggregatedFlows.size() == 3);

    AggregatedDnsKey firstKey("test.com", pcpp::DNS_TYPE_A, false);
    REQUIRE(aggregatedFlows[firstKey]->queries == 1);
    REQUIRE(aggregatedFlows[firstKey]->timeouts == 0);

    AggregatedDnsKey thirdKey("google.com", pcpp::DNS_TYPE_A, false);
    REQUIRE(aggregatedFlows[thirdKey]->queries == 1);
    REQUIRE(aggregatedFlows[thirdKey]->timeouts == 1);
}

TEST_CASE("Dns rcrd/rsps", "[dns]")
{
    spdlog::set_level(spdlog::level::debug);

    FlowstatsConfiguration conf;
    DisplayConfiguration displayConf;
    DnsStatsCollector dnsStats(conf, displayConf);

    readPcap("dns_rcrds.pcap", dnsStats);

    std::map<AggregatedDnsKey, AggregatedDnsFlow*> aggregatedFlows = dnsStats.getAggregatedFlow();
    REQUIRE(aggregatedFlows.size() == 1);

    AggregatedDnsKey udpKey("all.alb-metrics-agent-shard1-770518637.us-east-1.elb.amazonaws.com", pcpp::DNS_TYPE_A, false);
    REQUIRE(aggregatedFlows[udpKey]->queries == 1);
    REQUIRE(aggregatedFlows[udpKey]->totalRecords == 48);
}
