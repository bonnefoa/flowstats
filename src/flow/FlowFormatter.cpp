#include "FlowFormatter.hpp"
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <utility>

#include <utility>

namespace flowstats {

FlowFormatter::FlowFormatter() {};

FlowFormatter::FlowFormatter(
    std::vector<Field> displayKeys)
    : displayKeys(std::move(displayKeys)) {};

FlowFormatter::FlowFormatter(
    std::vector<Field> displayKeys,
    std::vector<Field> displayValues)
    : displayKeys(std::move(displayKeys))
    , displayValues(std::move(displayValues)) {};

auto FlowFormatter::outputKey(std::map<Field,
    std::string> const& values) const -> std::string
{
    fmt::memory_buffer keyBuf;
    for (auto& el : displayKeys) {
        fmt::format_to(keyBuf, fieldToFormat(el), values.at(el));
    }
    return to_string(keyBuf);
}

auto FlowFormatter::outputValue(std::map<Field,
    std::string> const& values) const -> std::string
{
    fmt::memory_buffer valueBuf;
    for (auto& el : displayValues) {
        fmt::format_to(valueBuf, fieldToFormat(el), values.at(el));
    }
    return to_string(valueBuf);
}

auto FlowFormatter::outputHeaders(std::string& keyHeaders,
    std::string& valueHeaders) const -> void
{
    fmt::memory_buffer keyBuf;
    for (auto& el : displayKeys) {
        fmt::format_to(keyBuf, fieldToFormat(el), fieldToHeader(el));
    }
    keyHeaders = to_string(keyBuf);

    fmt::memory_buffer valueBuf;
    for (auto& el : displayValues) {
        fmt::format_to(valueBuf, fieldToFormat(el), fieldToHeader(el));
    }
    valueHeaders = to_string(valueBuf);
}

void FlowFormatter::setDisplayKeys(std::vector<Field> const& keys)
{
    displayKeys = keys;
}

void FlowFormatter::setDisplayValues(std::vector<Field> const& values)
{
    displayValues = values;
}
} // namespace flowstats
