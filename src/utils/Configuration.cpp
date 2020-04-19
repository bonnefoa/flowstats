#include "Configuration.hpp"

namespace flowstats {

auto sortToString(enum SortType sortType) -> std::string
{
    switch (sortType) {
    case SortFqdn:
        return "Fqdn";
    case SortByte:
        return "Byte";
    case SortPacket:
        return "Packet";
    case SortRequest:
        return "Request";
    case SortRequestRate:
        return "RequestRate";
    case SortSrt:
        return "Srt";
    default:
        return "Unknown";
    }
}

auto displayTypeToString(enum DisplayType displayType) -> std::string
{
    switch (displayType) {
    case DisplayRequests:
        return "Requests";
    case DisplayResponses:
        return "Responses";
    case DisplayClients:
        return "Clients";
    case DisplayFlags:
        return "Flags";
    case DisplayConnections:
        return "Connections";
    case DisplayTraffic:
        return "Traffic";
    default:
        return "Unknown";
    }
}
}  // namespace flowstats
