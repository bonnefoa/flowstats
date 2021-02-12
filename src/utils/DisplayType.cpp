#include "DisplayType.hpp"

namespace flowstats {

auto displayTypeToString(enum DisplayType displayType) -> std::string
{
    switch (displayType) {
        case DisplayRequests: return "Requests";
        case DisplayResponses: return "Responses";
        case DisplayClients: return "Clients";
        case DisplaySsl: return "Ssl details";
        case DisplayDnsResourceRecords: return "Resource Records";

        case DisplayTcpFlags: return "Tcp Flags";
        case DisplayOtherFlags: return "Rst/0win";

        case DisplayConnections: return "Connections";
        case DisplayConnectionTimes: return "Conn Times";
        case DisplayTraffic: return "Traffic";
        default:
            return "Unknown";
    }
}
} // namespace flowstats
