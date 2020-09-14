#pragma once

#include "Configuration.hpp"
#include "Field.hpp"
#include "Flow.hpp"
#include "Utils.hpp"
#include <map>
#include <string>
#include <vector>

namespace flowstats {

class FlowFormatter {

public:
    FlowFormatter();
    virtual ~FlowFormatter() = default;

    [[nodiscard]] auto outputBody(Flow const* flow, Direction direction, int duration) const -> std::string;
    [[nodiscard]] auto outputHeaders() const -> std::string;

    [[nodiscard]] auto getDisplayFields() const& { return displayFields; };
    [[nodiscard]] auto getFieldToSize() const& { return fieldToSize; };
    auto setDisplayKeys(std::vector<Field> const& keys) { displayKeys = keys; };
    auto setDisplayValues(std::vector<Field> const& values)
    {
        displayFields = displayKeys;
        displayFields.insert(displayFields.end(), values.begin(), values.end());
    };

    auto outputFlow(Flow const* totalFlow,
        std::vector<Flow const*> const& aggregatedFlows,
        int duration, int maxResult) const -> std::vector<std::string>;

    auto updateFieldSize(int fieldIndex, int delta) -> void;

private:
    std::vector<Field> displayKeys;
    // Combine Keys and values in in a single vector
    std::vector<Field> displayFields;
    std::vector<int> fieldToSize;
};

} // namespace flowstats
