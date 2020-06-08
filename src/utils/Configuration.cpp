#include "Configuration.hpp"
#include <spdlog/logger.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace flowstats {

static auto setupLog()
{
    auto errLogger = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    errLogger->set_level(spdlog::level::warn);
    errLogger->set_pattern("[multi_sink_example] [%^%l%$] %v");

    auto fileLogger = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/multisink.txt", true);
    fileLogger->set_level(spdlog::level::trace);

    std::initializer_list<spdlog::sink_ptr> sinks = { errLogger, fileLogger };
    auto logger = std::make_shared<spdlog::logger>("multi_sink", sinks);

    logger->set_level(spdlog::level::debug);
    spdlog::set_default_logger(logger);
}

FlowReplayConfiguration::FlowReplayConfiguration()
{
    setupLog();
}

FlowstatsConfiguration::FlowstatsConfiguration()
{
    setupLog();
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
