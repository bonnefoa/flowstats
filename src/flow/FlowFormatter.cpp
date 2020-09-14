#include "FlowFormatter.hpp"
#include <fmt/format.h>

#include <utility>

#include <utility>

namespace flowstats {

FlowFormatter::FlowFormatter()
{
    fieldToSize.resize(Field::_size());
    for (size_t i = 0; i < Field::_size(); ++i) {
        fieldToSize[i] = 8;
    }
    fieldToSize[Field::FQDN] = 42;

    fieldToSize[Field::TRUNC] = 6;
    fieldToSize[Field::TYPE] = 6;
    fieldToSize[Field::DIR] = 6;

    fieldToSize[Field::DOMAIN] = 34;

    fieldToSize[Field::BYTES] = 10;

    fieldToSize[Field::TOP_CLIENT_IPS] = 60;

    fieldToSize[Field::IP] = 16;

    fieldToSize[Field::PORT] = 5;
    fieldToSize[Field::PROTO] = 5;
}

auto FlowFormatter::outputBody(Flow const* flow, Direction direction, int duration) const -> std::string
{
    fmt::memory_buffer bodyBuf;
    for (auto const& field : displayFields) {
        std::string content = flow->getFieldStr(field, direction, duration);
        fmt::format_to(bodyBuf, "{:<{}.{}} ", content, fieldToSize[field], fieldToSize[field]);
    }

    return to_string(bodyBuf);
}

auto FlowFormatter::outputHeaders() const -> std::string
{
    fmt::memory_buffer headersBuf;
    for (auto const& field : displayFields) {
        fmt::format_to(headersBuf, "{:<{}.{}} ", fieldToHeader(field), fieldToSize[field], fieldToSize[field]);
    }
    return to_string(headersBuf);
}

auto FlowFormatter::outputFlow(Flow const* totalFlow,
    std::vector<Flow const*> const& aggregatedFlows,
    int duration, int maxResult) const -> std::vector<std::string>
{
    std::vector<std::string> res;
    for (int j = FROM_CLIENT; j <= FROM_SERVER; ++j) {
        auto direction = static_cast<Direction>(j);
        res.push_back(outputBody(totalFlow, direction, duration));
    }
    for (auto const* flow : aggregatedFlows) {
        for (int j = FROM_CLIENT; j <= FROM_SERVER; ++j) {
            auto direction = static_cast<Direction>(j);
            res.push_back(outputBody(flow, direction, duration));
        }
    }
    return res;
}

auto FlowFormatter::updateFieldSize(int fieldIndex, int delta) -> void
{
    auto field = displayFields[fieldIndex];
    auto& fieldSize = fieldToSize[field];
    fieldSize = std::max(fieldSize + delta, 0);
}

} // namespace flowstats
