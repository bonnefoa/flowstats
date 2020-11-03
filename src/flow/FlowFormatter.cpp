#include "FlowFormatter.hpp"
#include <fmt/format.h>
#include <utility>

namespace flowstats {

auto FlowFormatter::outputLine(Flow const* flow,
    int duration, DisplayConfiguration const& displayConf,
    int index, std::vector<Field> const& displayFields,
    Direction direction) const -> std::string
{
    fmt::memory_buffer mergedBuf;
    for (auto const& displayField : displayFields) {
        auto field = fieldWithRateMode(displayConf.getRateMode(), displayField);
        if (displayConf.isFieldHidden(field)) {
            continue;
        }
        auto fieldSize = displayConf.getFieldToSize()[field];
        fmt::format_to(mergedBuf, "{:<{}.{}}| ",
            flow->getFieldStr(field, direction, duration, index), fieldSize, fieldSize);
    }
    return to_string(mergedBuf);
}

auto FlowFormatter::outputBodyWithSubfields(Flow const* flow,
    std::vector<std::string>* accumulator, int duration,
    DisplayConfiguration const& displayConf) const -> void
{
    int numSubfields = 0;
    for (auto const& field : displayFields) {
        auto size = flow->getSubfieldSize(field);
        if (size > numSubfields) {
            numSubfields = size;
        }
    }
    for (int i = 0; i < numSubfields; ++i) {
        auto line = outputLine(flow, duration, displayConf, i, displayFields, MERGED);
        accumulator->push_back(line);
    }
}

auto FlowFormatter::outputBody(Flow const* flow, std::vector<std::string>* accumulator,
    int duration, DisplayConfiguration const& displayConf) const -> void
{
    if (displayConf.getMergeDirection()) {
        auto line = outputLine(flow, duration, displayConf, 0, displayFields, MERGED);
        accumulator->push_back(line);
        return;
    }
    auto clientLine = outputLine(flow, duration, displayConf, 0, displayFields, FROM_CLIENT);
    auto serverLine = outputLine(flow, duration, displayConf, 0, displayFields, FROM_SERVER);
    accumulator->push_back(clientLine);
    accumulator->push_back(serverLine);
}

auto FlowFormatter::outputHeaders(DisplayConfiguration const& displayConf) const -> std::string
{
    fmt::memory_buffer headersBuf;
    auto fieldToSize = displayConf.getFieldToSize();
    for (auto const& displayField : displayFields) {
        auto field = fieldWithRateMode(displayConf.getRateMode(), displayField);
        if (displayConf.isFieldHidden(field)) {
            continue;
        }
        fmt::format_to(headersBuf, "{:<{}.{}}| ", fieldToHeader(field), fieldToSize[field], fieldToSize[field]);
    }
    return to_string(headersBuf);
}

auto FlowFormatter::outputFlow(std::vector<Flow const*> const& aggregatedFlows,
    int duration, DisplayConfiguration const& displayConf) const -> std::vector<std::string>
{
    std::vector<std::string> res;
    int i = 0;
    for (auto const* flow : aggregatedFlows) {
        if (i++ > displayConf.getMaxResults()) {
            break;
        };
        if (subfields.empty()) {
            outputBody(flow, &res, duration, displayConf);
        } else {
            outputBodyWithSubfields(flow, &res, duration, displayConf);
        }
    }
    return res;
}

} // namespace flowstats
