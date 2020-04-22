#include "Configuration.hpp"
#include "DnsStatsCollector.hpp"
#include "PktSource.hpp"
#include "Screen.hpp"
#include "SslStatsCollector.hpp"
#include "TcpStatsCollector.hpp"
#include "Utils.hpp"
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <netinet/in.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>

using namespace flowstats;

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
    { "verbose", no_argument, nullptr, 'v' },
    { "per-ip-aggr", no_argument, nullptr, 'w' },
    { "list-interfaces", no_argument, nullptr, 'l' },
    { "help", no_argument, nullptr, 'h' },
    { nullptr, 0, nullptr, 0 }
};

/**
 * Print application usage
 */
void printUsage()
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
    FlowstatsConfiguration conf;
    DisplayConfiguration displayConf;

    std::string agentAddr = "";
    std::string localhostIp = "";
    std::vector<std::string> initialDomains;
    std::vector<std::string> initialServerPorts;

    int optionIndex = 0;
    char opt = 0;

    while ((opt = getopt_long(argc, argv, "k:i:a:f:o:b:m:p:d:nuwhvl", FlowStatsOptions,
                &optionIndex))
        != -1) {
        switch (opt) {
        case 0:
            break;
        case 'b':
            conf.bpfFilter = optarg;
            break;
        case 'i':
            conf.interfaceNameOrIP = optarg;
            break;
        case 'a':
            agentAddr = optarg;
            break;
        case 'm':
            displayConf.maxResults = atoi(optarg);
            break;
        case 'f':
            conf.pcapFileName = optarg;
            break;
        case 'p':
            localhostIp = optarg;
            break;
        case 'k':
            initialServerPorts = split(optarg, ',');
            break;
        case 'd':
            initialDomains = split(optarg, ',');
            break;
        case 'v':
            spdlog::set_level(spdlog::level::debug);
            break;
        case 'h':
            printUsage();
            break;

        case 'u':
            conf.displayUnknownFqdn = true;
            break;
        case 'n':
            conf.noCurses = true;
            break;
        case 'w':
            conf.perIpAggr = true;
            break;
        case 'l':
            listInterfaces();
            break;
        default:
            printUsage();
            exit(-1);
        }
    }

    if (conf.pcapFileName == "" && conf.interfaceNameOrIP == "") {
        EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");
    }

    auto file_logger = spdlog::basic_logger_mt("basic_logger", "flowstats.log");
    spdlog::set_default_logger(file_logger);
    spdlog::set_pattern("[%H:%M:%S %z] [thread %t] %v");

    conf.agentConf = DogFood::Configure(agentAddr);
    std::vector<Collector*> collectors;
    conf.ipToFqdn = getIpToFqdn(initialDomains);
    conf.domainToServerPort = getDomainToServerPort(initialServerPorts);

    collectors.push_back(
        new DnsStatsCollector(conf, displayConf));
    collectors.push_back(new SslStatsCollector(conf, displayConf));
    collectors.push_back(
        new TcpStatsCollector(conf, displayConf));

    if (!localhostIp.empty()) {
        conf.ipToFqdn[Tins::IPv4Address(localhostIp)] = "localhost";
    }
    if (conf.pcapFileName != "") {
        analyzePcapFile(conf, collectors);
    } else {
        std::vector<Tins::IPv4Address> localIps = getLocalIps();
        for (auto& ip : localIps) {
            conf.ipToFqdn[ip] = "localhost";
        }
        std::atomic_bool shouldStop = false;
        Screen screen(shouldStop, conf.noCurses, conf,
            displayConf, collectors);
        screen.StartDisplay();
        auto dev = getLiveDevice(conf);
        analyzeLiveTraffic(dev, conf, collectors,
            shouldStop, screen);
    }

    for (auto* collector : collectors) {
        delete collector;
    }
}
