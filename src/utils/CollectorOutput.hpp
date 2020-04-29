#pragma once

#include "Configuration.hpp"
#include <string>
#include <vector>

namespace flowstats {
struct CollectorOutput {

    CollectorOutput() = default;
    CollectorOutput(std::string name, std::vector<std::string> keys,
        std::vector<std::string> values,
        std::string keyHeaders, std::string valueHeaders,
        int delta)
        : name(std::move(name))
        , keys(std::move(keys))
        , values(std::move(values))
        , keyHeaders(std::move(keyHeaders))
        , valueHeaders(std::move(valueHeaders))
        , delta(delta) {};

    auto print() const -> void;

    [[nodiscard]] auto getKeys() const { return keys; };
    [[nodiscard]] auto getKeyHeaders() const { return keyHeaders; };
    [[nodiscard]] auto getValues() const { return values; };
    [[nodiscard]] auto getValueHeaders() const { return valueHeaders; };

private:
    std::string name;
    std::vector<std::string> keys;
    std::vector<std::string> values;
    std::string keyHeaders;
    std::string valueHeaders;
    int delta;
};
} // namespace flowstats
