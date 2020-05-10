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
    virtual ~FlowFormatter() {};

    auto outputKey(std::map<Field, std::string> const& values) const -> std::string;
    auto outputValue(std::map<Field, std::string> const& values) const -> std::string;
    auto outputHeaders(std::string& keyHeaders, std::string& valueHeaders) const -> void;

    void setDisplayKeys(std::vector<Field> const& keys);
    void setDisplayValues(std::vector<Field> const& values);

private:
    std::vector<Field> displayKeys;
    std::vector<Field> displayValues;
};

} // namespace flowstats
