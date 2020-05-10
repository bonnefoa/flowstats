#include "FlowFormatter.hpp"
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <utility>

#include <utility>

namespace flowstats {

FlowFormatter::FlowFormatter() {};

auto FlowFormatter::outputKey(std::map<Field,
    std::string> const& values) const -> std::string
{
    fmt::memory_buffer keyBuf;
    for (auto& el : displayKeys) {
        auto it = values.find(el);
        if (it == values.end()) {
            fmt::format_to(keyBuf, fieldToFormat(el), "");
        } else {
            fmt::format_to(keyBuf, fieldToFormat(el), it->second);
        }
    }
    return to_string(keyBuf);
}

auto FlowFormatter::outputValue(std::map<Field,
    std::string> const& values) const -> std::string
{
    fmt::memory_buffer valueBuf;
    for (auto& el : displayValues) {
        auto it = values.find(el);
        if (it == values.end()) {
            fmt::format_to(valueBuf, fieldToFormat(el), "");
        } else {
            fmt::format_to(valueBuf, fieldToFormat(el), it->second);
        }
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
    displayKeys = std::move(keys);
}

void FlowFormatter::setDisplayValues(std::vector<Field> const& values)
{
    displayValues = values;
}
} // namespace flowstats
