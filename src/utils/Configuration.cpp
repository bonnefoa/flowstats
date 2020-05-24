#include "Configuration.hpp"
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace flowstats {

FlowstatsConfiguration::FlowstatsConfiguration()
{
    errLogger = spdlog::stderr_color_mt("stderr");
    errLogger->set_level(spdlog::level::err);

    auto fileLogger = spdlog::basic_logger_mt("basic_logger", "flowstats.log");
    fileLogger->set_pattern("[%H:%M:%S %z] [thread %t] %v");
    spdlog::set_default_logger(fileLogger);
}

auto displayTypeToString(enum DisplayType displayType) -> std::string
{
    switch (displayType) {
    case DisplayRequests:
        return "Requests";
    case DisplayResponses:
        return "Responses";
    case DisplayClients:
        return "Clients";
    case DisplayFlags:
        return "Flags";
    case DisplayConnections:
        return "Connections";
    case DisplayTraffic:
        return "Traffic";
    default:
        return "Unknown";
    }
}
} // namespace flowstats
