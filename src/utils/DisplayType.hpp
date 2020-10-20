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

class DisplayFieldValues {
public:
    explicit DisplayFieldValues(DisplayType displayType,
        std::vector<Field> fields, bool hasSubfields = false)
        : displayType(std::move(displayType))
        , fields(std::move(fields))
        , hasSubfields(hasSubfields) {};

    [[nodiscard]] auto getDisplayType() const { return displayType; };
    [[nodiscard]] auto getDisplayTypeStr() const { return displayTypeToString(displayType); };
    [[nodiscard]] auto getFields() const { return fields; };
    [[nodiscard]] auto getHasSubfields() const { return hasSubfields; };

private:
    DisplayType displayType;
    std::vector<Field> fields;
    bool hasSubfields;
};

//using DisplayPair = std::pair<DisplayType, DisplayFieldValues>;
} // namespace flowstats
