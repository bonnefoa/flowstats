#pragma once

#include "Configuration.hpp"
#include <string>
#include <vector>

namespace flowstats {
struct CollectorOutput {

    CollectorOutput() = default;
    CollectorOutput(std::string name,
        std::string headers,
        std::vector<std::vector<std::string>> values)
        : name(std::move(name))
        , headers(std::move(headers))
        , values(std::move(values)) {};

    auto print() const -> void;

    [[nodiscard]] auto getHeaders() const& -> std::string { return headers; };
    [[nodiscard]] auto getValues() const& -> std::vector<std::vector<std::string>> { return values; };

private:
    std::string name;
    std::string headers;
    std::vector<std::vector<std::string>> values;
};
} // namespace flowstats
