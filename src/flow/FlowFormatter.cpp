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

auto FlowFormatter::outputBody(std::map<Field,
    std::string> const& values) const -> std::string
{
    fmt::memory_buffer bodyBuf;
    for (auto const& field : displayKeys) {
        auto it = values.find(field);
        if (it == values.end()) {
            fmt::format_to(bodyBuf, "{:<{}.{}} ", "", fieldToSize[field], fieldToSize[field]);
        } else {
            fmt::format_to(bodyBuf, "{:<{}.{}} ", it->second, fieldToSize[field], fieldToSize[field]);
        }
    }
    for (auto const& field : displayValues) {
        auto it = values.find(field);
        if (it == values.end()) {
            fmt::format_to(bodyBuf, "{:<{}.{}} ", "", fieldToSize[field], fieldToSize[field]);
        } else {
            fmt::format_to(bodyBuf, "{:<{}.{}} ", it->second, fieldToSize[field], fieldToSize[field]);
        }
    }

    return to_string(bodyBuf);
}

auto FlowFormatter::outputHeaders() const -> std::string
{
    fmt::memory_buffer headersBuf;
    for (auto const& field : displayKeys) {
        fmt::format_to(headersBuf, "{:<{}.{}} ", fieldToHeader(field), fieldToSize[field], fieldToSize[field]);
    }
    for (auto const& field : displayValues) {
        fmt::format_to(headersBuf, "{:<{}.{}} ", fieldToHeader(field), fieldToSize[field], fieldToSize[field]);
    }
    return to_string(headersBuf);
}

} // namespace flowstats
