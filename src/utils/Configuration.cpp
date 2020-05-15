#include "Configuration.hpp"

namespace flowstats {

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
} // namespace flowstats
