#include "FlowFormatter.hpp"
#include <fmt/format.h>

#include <utility>

#include <utility>

namespace flowstats {

auto FlowFormatter::outputKey(std::map<Field,
    std::string> const& values) const -> std::string
{
    fmt::memory_buffer keyBuf;
    for (auto const& el : displayKeys) {
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
    for (auto const& el : displayValues) {
        auto it = values.find(el);
        if (it == values.end()) {
            fmt::format_to(valueBuf, fieldToFormat(el), "");
        } else {
            fmt::format_to(valueBuf, fieldToFormat(el), it->second);
        }
    }
    return to_string(valueBuf);
}

auto FlowFormatter::outputHeaders() const -> std::pair<std::string, std::string>
{
    fmt::memory_buffer keyBuf;
    for (auto const& el : displayKeys) {
        fmt::format_to(keyBuf, fieldToFormat(el), fieldToHeader(el));
    }
    auto keyHeaders = to_string(keyBuf);

    fmt::memory_buffer valueBuf;
    for (auto const& el : displayValues) {
        fmt::format_to(valueBuf, fieldToFormat(el), fieldToHeader(el));
    }
    auto valueHeaders = to_string(valueBuf);
    return std::pair(keyHeaders, valueHeaders);
}

} // namespace flowstats
