#include "Collector.hpp"
#include "DnsStatsCollector.hpp"
#include "SslStatsCollector.hpp"
#include "TcpStatsCollector.hpp"

using namespace flowstats;

int readPcap(const FlowstatsConfiguration& conf, Collector& collector,
    bool advanceTick = true);

class Tester {
public:
    Tester();
    virtual ~Tester() = default;

    auto readPcap(std::string pcap, std::string bpf = "",
        bool advanceTick = true) -> int;

    auto getDnsStatsCollector() const -> const DnsStatsCollector& { return dnsStatsCollector; }
    auto getTcpStatsCollector() const -> const TcpStatsCollector& { return tcpStatsCollector; }
    auto getSslStatsCollector() const -> const SslStatsCollector& { return sslStatsCollector; }
    auto getFlowstatsConfiguration() -> FlowstatsConfiguration& { return conf; }

private:
    DisplayConfiguration displayConf;
    FlowstatsConfiguration conf;

    DnsStatsCollector dnsStatsCollector;
    SslStatsCollector sslStatsCollector;
    TcpStatsCollector tcpStatsCollector;
    std::vector<Collector*> collectors;
};
