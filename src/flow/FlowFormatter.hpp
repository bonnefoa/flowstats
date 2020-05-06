#pragma once

#include "Configuration.hpp"
#include "Utils.hpp"
#include <map>
#include <string>
#include <vector>

namespace flowstats {

#define FQDN_SIZE 42
#define DIR_SIZE 6
#define DOMAIN_SIZE 34
#define IP_SIZE 16
#define PORT_SIZE 5
#define PROTO_SIZE 5
#define LEFT_ALIGN(size) "{:<" STR(size) "." STR(size) "} "

struct FlowFormatter {

    FlowFormatter();
    FlowFormatter(std::map<std::string, std::string> formatPatterns,
        std::map<std::string, std::string> headers,
        std::vector<std::string> displayKeys,
        std::vector<std::string> displayValues);
    virtual ~FlowFormatter() {};

    auto outputKey(std::map<std::string, std::string> const& values) const -> std::string;
    auto outputValue(std::map<std::string, std::string> const& values) const -> std::string;
    auto outputHeaders(std::string& keyHeaders, std::string& valueHeaders) const -> void;

    void setDisplayKeys(std::vector<std::string> const& keys);
    void setDisplayValues(std::vector<std::string> const& values);

private:
    std::map<std::string, std::string> formatPatterns;
    std::map<std::string, std::string> headers;
    std::vector<std::string> displayKeys;
    std::vector<std::string> displayValues;
};
} // namespace flowstats
