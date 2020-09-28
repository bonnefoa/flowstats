#pragma once

#include "Field.hpp"
#include <vector>

namespace flowstats {

enum DisplayType {
    DisplayRequests,
    DisplayResponses,
    DisplayClients,
    DisplayConnections,
    DisplayConnectionTimes,
    DisplayTcpFlags,
    DisplaySsl,
    DisplayOtherFlags,
    DisplayTraffic,
};

auto displayTypeToString(enum DisplayType displayType) -> std::string;
using DisplayPair = std::pair<DisplayType, std::vector<Field>>;
} // namespace flowstats
