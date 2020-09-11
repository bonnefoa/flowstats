#include "FlowFormatter.hpp"
#include <fmt/format.h>

#include <utility>

#include <utility>

namespace flowstats {

FlowFormatter::FlowFormatter() {
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

auto FlowFormatter::outputKey(std::map<Field,
    std::string> const& values) const -> std::string
{
    fmt::memory_buffer keyBuf;
    for (auto const& field : displayKeys) {
        auto it = values.find(field);
        if (it == values.end()) {
            fmt::format_to(keyBuf, "{:<{}.{}} ", "", fieldToSize[field], fieldToSize[field]);
        } else {
            fmt::format_to(keyBuf, "{:<{}.{}} ", it->second, fieldToSize[field], fieldToSize[field]);
        }
    }
    return to_string(keyBuf);
}

auto FlowFormatter::outputValue(std::map<Field,
    std::string> const& values) const -> std::string
{
    fmt::memory_buffer valueBuf;
    for (auto const& field : displayValues) {
        auto it = values.find(field);
        if (it == values.end()) {
            fmt::format_to(valueBuf, "{:<{}.{}} ", "", fieldToSize[field], fieldToSize[field]);
        } else {
            fmt::format_to(valueBuf, "{:<{}.{}} ", it->second, fieldToSize[field], fieldToSize[field]);
        }
    }
    return to_string(valueBuf);
}

auto FlowFormatter::outputHeaders() const -> std::pair<std::string, std::string>
{
    fmt::memory_buffer keyBuf;
    for (auto const& field : displayKeys) {
        fmt::format_to(keyBuf, "{:<{}.{}} ", fieldToHeader(field), fieldToSize[field], fieldToSize[field]);
    }
    auto keyHeaders = to_string(keyBuf);

    fmt::memory_buffer valueBuf;
    for (auto const& field : displayValues) {
        fmt::format_to(valueBuf, "{:<{}.{}} ", fieldToHeader(field), fieldToSize[field], fieldToSize[field]);
    }
    auto valueHeaders = to_string(valueBuf);
    return std::pair(keyHeaders, valueHeaders);
}

} // namespace flowstats
