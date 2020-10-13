#include "Configuration.hpp"
#include <spdlog/logger.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace flowstats {

LogConfiguration::LogConfiguration()
{
    auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    consoleSink->set_level(spdlog::level::warn);
    consoleSink->set_pattern("[%^%l%$] %v");

    auto fileLogger = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/multisink.txt", true);
    fileLogger->set_level(spdlog::level::trace);

    std::initializer_list<spdlog::sink_ptr> sinks = { consoleSink, fileLogger };
    logger = std::make_shared<spdlog::logger>("multi_sink", sinks);

    logger->set_level(spdlog::level::info);
    spdlog::set_default_logger(logger);
}

} // namespace flowstats
