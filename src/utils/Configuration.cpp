#include "Configuration.hpp"
#include <spdlog/logger.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace flowstats {

LogConfiguration::LogConfiguration()
{
    auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    consoleSink->set_level(spdlog::level::warn);
    consoleSink->set_pattern("[multi_sink_example] [%^%l%$] %v");

    auto fileLogger = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/multisink.txt", true);
    fileLogger->set_level(spdlog::level::trace);

    std::initializer_list<spdlog::sink_ptr> sinks = { consoleSink, fileLogger };
    logger = std::make_shared<spdlog::logger>("multi_sink", sinks);

    logger->set_level(spdlog::level::info);
    spdlog::set_default_logger(logger);
}

DisplayConfiguration::DisplayConfiguration()
{
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

auto DisplayConfiguration::updateFieldSize(Field field, int delta) -> void
{
    auto& fieldSize = fieldToSize[field];
    fieldSize = std::max(fieldSize + delta, 0);
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
