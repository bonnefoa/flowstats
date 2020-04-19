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

    std::string outputKey(std::map<std::string, std::string>& values);
    std::string outputValue(std::map<std::string, std::string>& values);
    void outputHeaders(std::string& keyHeaders, std::string& valueHeaders);

    void setDisplayKeys(const std::vector<std::string>& keys);
    void setDisplayValues(const std::vector<std::string>& values);

private:
    std::map<std::string, std::string> formatPatterns;
    std::map<std::string, std::string> headers;
    std::vector<std::string> displayKeys;
    std::vector<std::string> displayValues;
};
}
