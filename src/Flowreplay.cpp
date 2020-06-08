#include "Configuration.hpp"
#include "Utils.hpp"
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <tins/network_interface.h>
#include <tins/rawpdu.h>
#include <tins/sniffer.h>

#define EXIT_WITH_ERROR(reason, ...)                      \
    do {                                                  \
        printf("\nError: " reason "\n\n", ##__VA_ARGS__); \
        printUsage();                                     \
        exit(1);                                          \
    } while (0)

static struct option FlowReplayOptions[] = {
    { "dest-ip", required_argument, nullptr, 'd' },
    { "dest-port", required_argument, nullptr, 'p' },
    { "input-file", required_argument, nullptr, 'f' },
    { "bpf-filter", required_argument, nullptr, 'b' },

    { "verbose", no_argument, nullptr, 'v' },
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
           "flowreplay -f pcap_file -d iface -hv \n"
           "\nOptions:\n\n"
           "    -f           : The input pcap/pcapng file to replay\n"
           "    -d           : The ip to target\n"
           "    -b           : Bpf filter to apply\n"
           "    -v           : Verbose log\n"
           "    -h           : Displays this help message and exits\n\n");
    exit(0);
}

static auto openSocket(struct sockaddr_in server, uint16_t port)
{
    auto sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_port = htons(port);

    connect(sock, (const sockaddr*)&server, sizeof(server));
    return sock;
}

/**
 * main method of this utility
 */
auto main(int argc, char* argv[]) -> int
{
    flowstats::FlowReplayConfiguration conf;

    int optionIndex = 0;
    int opt = 0;

    while ((opt = getopt_long(argc, argv, "f:d:b:p:vh", FlowReplayOptions,
                &optionIndex))
        != -1) {
        switch (opt) {
        case 0:
            break;
        case 'b':
            conf.setBpfFilter(optarg);
            break;
        case 'f':
            conf.setPcapFileName(optarg);
            break;
        case 'p':
            conf.setDstPort(atoi(optarg));
            break;
        case 'd':
            conf.setIp(optarg);
            break;
        case 'v':
            spdlog::set_level(spdlog::level::debug);
            break;
        case 'h':
            printUsage();
            break;
        default:
            printUsage();
            exit(-1);
        }
    }

    if (conf.getPcapFileName() == "" && conf.getIp() == "") {
        EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");
    }

    auto* reader = new Tins::FileSniffer(conf.getPcapFileName(), conf.getBpfFilter());
    if (reader == nullptr) {
        spdlog::error("Could not open pcap {}", conf.getPcapFileName());
        exit(-1);
    }

    struct in_addr ipv4addr;
    inet_pton(AF_INET, conf.getIp().c_str(), &ipv4addr);
    auto hp = gethostbyaddr(&ipv4addr, sizeof ipv4addr, AF_INET);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    bcopy(hp->h_addr, &(server.sin_addr.s_addr), hp->h_length);

    std::map<uint16_t, int> portToSocket;
    for (auto packet : *reader) {
        auto const* pdu = packet.pdu();
        auto const* ip = pdu->find_pdu<Tins::IP>();
        if (ip == nullptr) {
            continue;
        }
        auto const* tcp = ip->find_pdu<Tins::TCP>();
        if (tcp == nullptr) {
            continue;
        }

        auto dstPort = tcp->dport();
        auto it = portToSocket.find(dstPort);
        int sockFd = 0;
        if (it == portToSocket.end()) {
            sockFd = openSocket(server, dstPort);
            portToSocket.insert({ dstPort, sockFd });
        } else {
            sockFd = it->second;
        }
        auto rawPDU = tcp->find_pdu<Tins::RawPDU>();
        if (rawPDU == nullptr) {
            continue;
        }
        send(sockFd, &rawPDU->payload()[0], rawPDU->payload_size(), 0);
    }
}
