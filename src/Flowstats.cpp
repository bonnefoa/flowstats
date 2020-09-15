#include "Configuration.hpp"
#include "DnsStatsCollector.hpp"
#include "IpToFqdn.hpp"
#include "PktSource.hpp"
#include "Screen.hpp"
#include "SslStatsCollector.hpp"
#include "TcpStatsCollector.hpp"
#include "Utils.hpp"
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <netinet/in.h>

#define EXIT_WITH_ERROR(reason, ...)                      \
    do {                                                  \
        printf("\nError: " reason "\n\n", ##__VA_ARGS__); \
        printUsage();                                     \
        exit(1);                                          \
    } while (0)

static struct option FlowStatsOptions[] = {
    { "interface", required_argument, nullptr, 'i' },
    { "input-file", required_argument, nullptr, 'f' },
    { "datadog-agent-addr", required_argument, nullptr, 'a' },
    { "localhost-ip", required_argument, nullptr, 'p' },
    { "bpf-filter", required_argument, nullptr, 'b' },
    { "max-results", required_argument, nullptr, 'm' },
    { "resolve-domains", required_argument, nullptr, 'd' },
    { "server-ports", required_argument, nullptr, 'k' },

    { "ignore-unknown-fqdn", no_argument, nullptr, 'u' },
    { "no-curses", no_argument, nullptr, 'n' },
    { "no-display", no_argument, nullptr, 'c' },
    { "verbose", no_argument, nullptr, 'v' },
    { "per-ip-aggr", no_argument, nullptr, 'w' },
    { "list-interfaces", no_argument, nullptr, 'l' },
    { "help", no_argument, nullptr, 'h' },
    { nullptr, 0, nullptr, 0 }
};

/**
 * Print application usage
 */
static auto printUsage()
{
    printf("\nUsage: \n"
           "----------------------\n"
           "flowstats -f input_file -i iface [-m maxResults] [-a ddagentAddr] -hvl \n"
           "\nOptions:\n\n"
           "    -f           : The input pcap/pcapng file to analyze\n"
           "    -i           : The iface to capture\n"
           "    -a           : Address of the ddagent\n"
           "    -b           : Bpf filter to apply\n"
           "    -m           : Maximum number of result to display\n"
           "    -v           : Verbose log\n"
           "    -h           : Displays this help message and exits\n"
           "    -l           : Print the list of interfaces and exists\n\n");
    exit(0);
}

/**
 * main method of this utility
 */
auto main(int argc, char* argv[]) -> int
{
    flowstats::FlowstatsConfiguration conf;
    flowstats::DisplayConfiguration displayConf;

    std::string agentAddr = "";
    std::string localhostIp = "";
    std::vector<std::string> initialDomains;
    std::vector<std::string> initialServerPorts;

    int optionIndex = 0;
    int opt = 0;
    bool noDisplay = false;
    bool noCurses = false;
    bool pcapReplay = false;

    while ((opt = getopt_long(argc, argv, "k:i:a:f:o:b:m:p:d:cnuwhvl", FlowStatsOptions,
                &optionIndex))
        != -1) {
        switch (opt) {
        case 0:
            break;
        case 'b':
            conf.setBpfFilter(optarg);
            break;
        case 'i':
            conf.setIface(optarg);
            break;
        case 'a':
            agentAddr = optarg;
            break;
        case 'm':
            displayConf.setMaxResults(atoi(optarg));
            break;
        case 'f':
            conf.setPcapFileName(optarg);
            break;
        case 'p':
            localhostIp = optarg;
            break;
        case 'k':
            initialServerPorts = flowstats::split(optarg, ',');
            break;
        case 'd':
            initialDomains = flowstats::split(optarg, ',');
            break;
        case 'v':
            conf.setLogDebug();
            break;
        case 'h':
            printUsage();
            break;

        case 'u':
            conf.setDisplayUnknownFqdn(true);
            break;
        case 'n':
            noDisplay = true;
            break;
        case 'c':
            noCurses = true;
            break;
        case 'w':
            conf.setPerIpAggr(true);
            break;
        case 'l':
            flowstats::listInterfaces();
            break;
        default:
            printUsage();
            exit(-1);
        }
    }

    if (conf.getPcapFileName() == "" && conf.getInterfaceName() == "") {
        EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");
    }

    conf.setAgentConf(DogFood::Configure(agentAddr));
    pcapReplay = conf.getPcapFileName() != "";
    std::vector<flowstats::Collector*> collectors;
    conf.setDomainToServerPort(flowstats::getDomainToServerPort(initialServerPorts));

    flowstats::IpToFqdn ipToFqdn(conf, initialDomains, localhostIp);

    collectors.push_back(
        new flowstats::DnsStatsCollector(conf, displayConf, &ipToFqdn));
    collectors.push_back(new flowstats::SslStatsCollector(conf,
        displayConf, &ipToFqdn));
    collectors.push_back(
        new flowstats::TcpStatsCollector(conf, displayConf, &ipToFqdn));

    std::atomic_bool shouldStop = false;
    flowstats::Screen screen(&shouldStop, &displayConf,
            noCurses, noDisplay, pcapReplay, collectors);
    flowstats::PktSource pktSource(&screen, conf, collectors, &shouldStop);
    screen.StartDisplay();
    if (pcapReplay) {
        pktSource.analyzePcapFile();
    } else {
        std::vector<Tins::IPv4Address> localIps = pktSource.getLocalIps();
        ipToFqdn.updateFqdn("localhost", localIps, {});
        pktSource.analyzeLiveTraffic();
    }

    for (auto* collector : collectors) {
        delete collector;
    }
}
