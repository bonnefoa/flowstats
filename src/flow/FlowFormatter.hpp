#pragma once

#include "Configuration.hpp"
#include "Field.hpp"
#include "Utils.hpp"
#include <map>
#include <string>
#include <vector>

namespace flowstats {

struct FlowFormatter {

    FlowFormatter();
    virtual ~FlowFormatter() = default;

    [[nodiscard]] auto outputBody(std::map<Field, std::string> const& values) const -> std::string;
    [[nodiscard]] auto outputHeaders() const -> std::string;

    [[nodiscard]] auto getDisplayKeys() const { return displayKeys; };
    auto setDisplayKeys(std::vector<Field> const& keys) { displayKeys = keys; };
    auto setDisplayValues(std::vector<Field> const& values) { displayValues = values; };

private:
    std::vector<Field> displayKeys;
    std::vector<Field> displayValues;
    std::vector<int>   fieldToSize;
};

} // namespace flowstats
