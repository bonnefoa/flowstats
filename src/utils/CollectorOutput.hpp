#pragma once

#include "Configuration.hpp"
#include <string>
#include <vector>

namespace flowstats {
struct CollectorOutput {
    std::string name;

    std::vector<std::string> keys;
    std::vector<std::string> values;

    std::string keyHeaders;
    std::string valueHeaders;
    int delta;

    CollectorOutput() {};

    CollectorOutput(std::string name, std::vector<std::string> keys,
        std::vector<std::string> values,
        std::string keyHeaders, std::string valueHeaders,
        int delta)
        : name(name)
        , keys(keys)
        , values(values)
        , keyHeaders(keyHeaders)
        , valueHeaders(valueHeaders)
        , delta(delta) {};

    void print();
};
}
