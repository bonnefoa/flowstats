#pragma once

#include "Configuration.hpp"
#include "DisplayConfiguration.hpp"
#include "DisplayType.hpp"
#include "Field.hpp"
#include "Flow.hpp"
#include "Utils.hpp"
#include <map>
#include <string>
#include <vector>

namespace flowstats {

class FlowFormatter {

public:
    FlowFormatter() = default;
    virtual ~FlowFormatter() = default;

    auto outputBody(Flow const* flow, std::vector<std::string>* accumulator,
        int duration, DisplayConfiguration const& displayConf) const -> void;
    auto outputBodyWithSubfields(Flow const* flow, std::vector<std::string>* accumulator,
            int duration, DisplayConfiguration const& displayConf) const -> void;

    [[nodiscard]] auto outputHeaders(DisplayConfiguration const& displayConf) const -> std::string;

    [[nodiscard]] auto getDisplayFields() const& { return displayFields; };
    auto setDisplayKeys(std::vector<Field> const& keys) { displayKeys = keys; };
    auto setDisplayValues(DisplayFieldValues const& values)
    {
        displayFields = displayKeys;
        auto const& fields = values.getFields();
        displayFields.insert(displayFields.end(), fields.begin(), fields.end());
        hasSubfields = values.getHasSubfields();
    };

    auto outputFlow(Flow const* totalFlow,
        std::vector<Flow const*> const& aggregatedFlows,
        int duration, DisplayConfiguration const& displayConf) const -> std::vector<std::string>;

private:
    std::vector<Field> displayKeys;
    // Combine Keys and values in in a single vector
    std::vector<Field> displayFields;
    bool hasSubfields = false;
};

} // namespace flowstats
