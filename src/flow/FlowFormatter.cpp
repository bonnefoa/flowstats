#include "FlowFormatter.hpp"
#include <fmt/format.h>
#include <utility>

namespace flowstats {

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
        fmt::memory_buffer mergedBuf;
        for (auto const& field : displayFields) {
            if (displayConf.isFieldHidden(field)) {
                continue;
            }
            auto fieldSize = displayConf.getFieldToSize()[field];
            fmt::format_to(mergedBuf, "| {:<{}.{}}",
                    flow->getFieldStr(field, MERGED, duration, i), fieldSize, fieldSize);
        }
        accumulator->push_back(to_string(mergedBuf));
    }
}

auto FlowFormatter::outputBody(Flow const* flow, std::vector<std::string>* accumulator,
    int duration, DisplayConfiguration const& displayConf) const -> void
{
    if (displayConf.getMergeDirection()) {
        fmt::memory_buffer mergedBuf;
        for (auto const& displayField : displayFields) {
            auto field = fieldWithRateMode(displayConf.getRateMode(), displayField);
            if (displayConf.isFieldHidden(field)) {
                continue;
            }
            auto fieldSize = displayConf.getFieldToSize()[field];
            fmt::format_to(mergedBuf, "| {:<{}.{}}", flow->getFieldStr(field, MERGED, duration), fieldSize, fieldSize);
        }
        accumulator->push_back(to_string(mergedBuf));
        return;
    }

    fmt::memory_buffer clientBuf;
    fmt::memory_buffer serverBuf;
    for (auto const& displayField : displayFields) {
        auto field = fieldWithRateMode(displayConf.getRateMode(), displayField);
        if (displayConf.isFieldHidden(field)) {
            continue;
        }
        std::string clientContent = flow->getFieldStr(field, FROM_CLIENT, duration);
        std::string serverContent = flow->getFieldStr(field, FROM_SERVER, duration);
        auto fieldSize = displayConf.getFieldToSize()[field];

        fmt::format_to(clientBuf, "| {:<{}.{}}", clientContent, fieldSize, fieldSize);

        if (serverContent == "" && clientContent.size() > fieldSize) {
            fmt::format_to(serverBuf, "| {:<{}.{}}", clientContent.substr(fieldSize), fieldSize, fieldSize);
        } else {
            fmt::format_to(serverBuf, "| {:<{}.{}}", serverContent, fieldSize, fieldSize);
        }
    }

    accumulator->push_back(to_string(clientBuf));
    accumulator->push_back(to_string(serverBuf));
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
        fmt::format_to(headersBuf, "| {:<{}.{}}", fieldToHeader(field), fieldToSize[field], fieldToSize[field]);
    }
    return to_string(headersBuf);
}

auto FlowFormatter::outputFlow(Flow const* totalFlow,
    std::vector<Flow const*> const& aggregatedFlows,
    int duration, DisplayConfiguration const& displayConf) const -> std::vector<std::string>
{
    std::vector<std::string> res;
    if (subfields.empty()) {
        outputBody(totalFlow, &res, duration, displayConf);
    } else {
        outputBodyWithSubfields(totalFlow, &res, duration, displayConf);
    }
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
