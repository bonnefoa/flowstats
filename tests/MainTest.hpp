#include "Collector.hpp"
#include "DnsStatsCollector.hpp"
#include "SslStatsCollector.hpp"
#include "TcpStatsCollector.hpp"

using namespace flowstats;

int readPcap(FlowstatsConfiguration const& conf, Collector& collector,
    bool advanceTick = true);

class Tester {
public:
    Tester(bool perIpAggr = false);
    virtual ~Tester() = default;

    auto readPcap(std::string pcap, std::string bpf = "",
        bool advanceTick = true) -> int;

    auto getDnsStatsCollector() const -> DnsStatsCollector const& { return dnsStatsCollector; }
    auto getDnsStatsCollector() -> DnsStatsCollector& { return dnsStatsCollector; }
    auto getTcpStatsCollector() const -> TcpStatsCollector const& { return tcpStatsCollector; }
    auto getSslStatsCollector() const -> SslStatsCollector const& { return sslStatsCollector; }
    auto getFlowstatsConfiguration() const -> FlowstatsConfiguration const& { return conf; }
    auto getIpToFqdn() -> IpToFqdn& { return ipToFqdn; }

private:
    DisplayConfiguration displayConf;
    FlowstatsConfiguration conf;
    IpToFqdn ipToFqdn;

    DnsStatsCollector dnsStatsCollector;
    SslStatsCollector sslStatsCollector;
    TcpStatsCollector tcpStatsCollector;
    std::vector<Collector*> collectors;
};
