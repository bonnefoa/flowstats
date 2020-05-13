#pragma once

#include "Configuration.hpp"
#include "Field.hpp"
#include "Utils.hpp"
#include <map>
#include <string>
#include <vector>

namespace flowstats {

struct FlowFormatter {

    FlowFormatter() = default;
    virtual ~FlowFormatter() = default;

    [[nodiscard]] auto outputKey(std::map<Field, std::string> const& values) const -> std::string;
    [[nodiscard]] auto outputValue(std::map<Field, std::string> const& values) const -> std::string;
    [[nodiscard]] auto outputHeaders() const -> std::pair<std::string, std::string>;

    void setDisplayKeys(std::vector<Field> const& keys);
    void setDisplayValues(std::vector<Field> const& values);

private:
    std::vector<Field> displayKeys;
    std::vector<Field> displayValues;
};

} // namespace flowstats
