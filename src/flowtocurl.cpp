#include "Configuration.hpp"
#include "PktSource.hpp"
#include "Screen.hpp"
#include "Utils.hpp"
#include <HttpLayer.h>
#include <PcapPlusPlusVersion.h>
#include <SystemUtils.h>
#include <cstdlib>
#include <cstring>
#include <fmt/format.h>
#include <getopt.h>
#include <netinet/in.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>

namespace flowstats {

using namespace Tins;

#define EXIT_WITH_ERROR(reason, ...)                      \
    do {                                                  \
        printf("\nError: " reason "\n\n", ##__VA_ARGS__); \
        printUsage();                                     \
        exit(1);                                          \
    } while (0)

static struct option FlowStatsOptions[] = {
    { "interface", required_argument, nullptr, 'i' },
    { "input-file", required_argument, nullptr, 'f' },
    { "bpf-filter", required_argument, nullptr, 'b' },
    { "http-server-ports", required_argument, nullptr, 'p' },
    { "exclude-headers", required_argument, nullptr, 'e' },
    { "exclude-uri", required_argument, nullptr, 'u' },
    { "api-key", required_argument, nullptr, 'a' },
    { "app-key", required_argument, nullptr, 's' },

    { "verbose", no_argument, nullptr, 'v' },
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
           "%s -f input_file -i iface -v \n"
           "\nOptions:\n\n"
           "    -f           : The input pcap/pcapng file to replay\n"
           "    -i           : The iface to send traffic to\n"
           "    -b           : Bpf filter to apply\n"
           "    -p           : Http server ports, separated by comma\n"
           "    -d           : Destination IP\n"
           "    -u           : Uri to exclude\n"

           "    -v           : Verbose log\n"
           "    -h           : Displays this help message and exits\n"
           "    -l           : Print the list of interfaces and exists\n\n",
        AppName::get().c_str());
    exit(0);
}

auto methodToString(HttpRequestLayer::HttpMethod method) -> std::string
{
    switch (method) {
    case HttpRequestLayer::HttpGET:
        return "GET";
    case HttpRequestLayer::HttpHEAD:
        return "HEAD";
    case HttpRequestLayer::HttpPOST:
        return "POST";
    case HttpRequestLayer::HttpPUT:
        return "PUT";
    case HttpRequestLayer::HttpDELETE:
        return "DELETE";
    case HttpRequestLayer::HttpTRACE:
        return "TRACE";
    case HttpRequestLayer::HttpOPTIONS:
        return "OPTIONS";
    case HttpRequestLayer::HttpCONNECT:
        return "CONNECT";
    case HttpRequestLayer::HttpPATCH:
        return "PATCH";
    case HttpRequestLayer::HttpMethodUnknown:
        return "UNKNOWN";
    }
}

struct CurlGeneratorConfiguration {
    std::set<int> httpServerPorts;
    std::string destinationIP;
    std::set<std::string> excludedHeaders;
    std::set<std::string> excludedUris;

    std::string interfaceNameOrIP = "";
    std::string apiKey = "";
    std::string appKey = "";
    std::string pcapFileName = "";
    std::string bpfFilter = "";

    CurlGeneratorConfiguration() = default;
    ;
};

void handleHttp(Packet& packet, Tins::TCP const& tcp, CurlGeneratorConfiguration& conf)
{
    int dstPort = ntohs(tcp->getTcpHeader()->portDst);
    if (conf.httpServerPorts.count(dstPort) == 0) {
        return;
    }
    uint8_t* payload = tcp->getLayerPayload();
    size_t payloadLen = tcp->getLayerPayloadSize();
    if (HttpRequestFirstLine::parseMethod(reinterpret_cast<char*>(payload), payloadLen) == HttpRequestLayer::HttpMethodUnknown) {
        return;
    }
    HttpRequestLayer request = HttpRequestLayer(payload, payloadLen, tcp, &packet);
    HttpRequestFirstLine* firstLine = request.getFirstLine();

    std::string destinationIP;
    if (conf.destinationIP == "") {
        auto* ipv4Layer = packet.getPrevLayerOfType<Tins::IP>(tcp);
        destinationIP = ipv4Layer->getDstIpAddress().toString();
    } else {
        destinationIP = conf.destinationIP;
    }
    HttpRequestLayer::HttpMethod method = firstLine->getMethod();
    std::string uri = firstLine->getUri();

    if (conf.excludedUris.count(uri) > 0) {
        return;
    }

    HeaderField* field = request.getFirstField();
    std::vector<std::string> headers = {};
    if (conf.apiKey != "" && conf.appKey != "") {
        headers.push_back(fmt::format("-H 'DD-API-KEY: {}'", conf.apiKey));
        headers.push_back(fmt::format("-H 'DD-APPLICATION-KEY: {}'", conf.appKey));
    }
    while (field != nullptr) {
        std::string fieldName = field->getFieldName();
        if (fieldName == "transfer-encoding" && field->getFieldValue() == "chunked") {
            return;
        }
        if (fieldName != "" && conf.excludedHeaders.count(fieldName) == 0) {
            headers.push_back(fmt::format("-H '{}:{}'", fieldName, field->getFieldValue()));
        }
        field = request.getNextField(field);
    }

    std::string parameters = "";
    if (method == HttpRequestLayer::HttpPOST) {
        size_t requestPayloadSize = request.getLayerPayloadSize();
        std::string payload = std::string(reinterpret_cast<char*>(request.getLayerPayload()), requestPayloadSize);
        payload[requestPayloadSize + 1] = '\0';
        if (payload != "") {
            parameters = fmt::format("-d '{}'", payload);
        }
    }

    fmt::print("\ncurl -X {} 'http://{}:{}{}' {} {}\n", methodToString(method),
        destinationIP, dstPort, uri, fmt::join(headers, " "), parameters);
}

/**
 * main method of this utility
 */
auto main(int argc, char* argv[]) -> int
{
    AppName::init(argc, argv);

    CurlGeneratorConfiguration conf;
    std::vector<std::string> httpServerPortStrs = { "3834", "80", "8080" };
    conf.excludedHeaders = { "content-length", "javascript-version",
        "user-agent", "sec-fetch-dest", "x-requested-with",
        "sec-fetch-site", "sec-fetch-mode", "cookie", "x-user", "referer", "x-iws-via", "accept-language",
        "x-cloud-trace-context", "via", "x-request-id", "x-client-ip", "origin" };

    int optionIndex = 0;
    char opt = 0;

    while ((opt = getopt_long(argc, argv, "e:i:f:b:p:d:u:a:s:hvl", FlowStatsOptions,
                &optionIndex))
        != -1) {
        switch (opt) {
        case 0:
            break;
        case 'a':
            conf.apiKey = optarg;
            break;
        case 's':
            conf.appKey = optarg;
            break;
        case 'b':
            conf.bpfFilter = optarg;
            break;
        case 'i':
            conf.interfaceNameOrIP = optarg;
            break;
        case 'p':
            httpServerPortStrs = split(optarg, ',');
            break;
        case 'd':
            conf.destinationIP = optarg;
            break;
        case 'f':
            conf.pcapFileName = optarg;
            break;
        case 'u':
            conf.excludedUris = splitSet(optarg, ',');
            break;
        case 'v':
            spdlog::set_level(spdlog::level::debug);
            break;
        case 'h':
            printUsage();
            break;
        case 'l':
            listInterfaces();
            break;
        default:
            printUsage();
            exit(-1);
        }
    }

    conf.httpServerPorts = stringsToInts(httpServerPortStrs);

    if (conf.pcapFileName == "" && conf.interfaceNameOrIP == "") {
        EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");
    }

    //PcapLiveDevice* dev = getLiveDevice(conf.interfaceNameOrIP);
    IFileReaderDevice* reader = getPcapReader(conf.pcapFileName, conf.bpfFilter);

    RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        Packet packet(&rawPacket, Tins::OsiModelTransportLayer);
        if (packet.isPacketOfType(Tins::TCP)) {
            auto* tcp = packet.getLayerOfType<Tins::TCP>();
            handleHttp(packet, tcp, conf);
        }
    }
}
} // namespace flowstats
