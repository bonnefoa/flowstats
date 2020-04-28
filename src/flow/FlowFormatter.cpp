#include "FlowFormatter.hpp"
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <utility>

#include <utility>

namespace flowstats {

FlowFormatter::FlowFormatter()
{
    formatPatterns["dir"] = LEFT_ALIGN(DIR_SIZE);
    formatPatterns["domain"] = LEFT_ALIGN(DOMAIN_SIZE);
    formatPatterns["fqdn"] = LEFT_ALIGN(FQDN_SIZE) " ";
    formatPatterns["ip"] = LEFT_ALIGN(IP_SIZE);
    formatPatterns["port"] = LEFT_ALIGN(PORT_SIZE);
    formatPatterns["proto"] = LEFT_ALIGN(PROTO_SIZE);

    formatPatterns["active_connections"] = "{:<8.8} ";
    formatPatterns["failed_connections"] = "{:<8.8} ";
    formatPatterns["close"] = "{:<8.8} ";
    formatPatterns["close_s"] = "{:<8.8} ";
    formatPatterns["conn"] = "{:<8.8}";
    formatPatterns["conn_s"] = "{:<8.8} ";
    formatPatterns["ctp95"] = "{:<8.8} ";
    formatPatterns["ctp99"] = "{:<8.8} ";

    formatPatterns["rcrd_rsp"] = "{:<8.8} ";
    formatPatterns["top_client_ips"] = "{:<60.60} ";
    formatPatterns["req"] = "{:<8.8} ";
    formatPatterns["req_s"] = "{:<8.8} ";

    formatPatterns["srt"] = "{:<8.8} ";
    formatPatterns["srt_s"] = "{:<8.8} ";
    formatPatterns["srt95"] = "{:<8.8} ";
    formatPatterns["srt99"] = "{:<8.8} ";
    formatPatterns["srtMax"] = "{:<8.8} ";

    formatPatterns["ds95"] = "{:<8.8} ";
    formatPatterns["ds99"] = "{:<8.8} ";
    formatPatterns["dsMax"] = "{:<8.8} ";

    formatPatterns["mtu"] = "{:<8.8} ";
    formatPatterns["pkts"] = "{:<8.8} ";
    formatPatterns["pkts_s"] = "{:<8.8} ";
    formatPatterns["bytes"] = "{:<10.10} ";
    formatPatterns["bytes_s"] = "{:<8.8} ";

    formatPatterns["syn"] = "{:<8.8} ";
    formatPatterns["synack"] = "{:<8.8} ";
    formatPatterns["zwin"] = "{:<8.8} ";
    formatPatterns["rst"] = "{:<8.8} ";
    formatPatterns["fin"] = "{:<8.8} ";

    formatPatterns["timeouts"] = "{:<8.8} ";
    formatPatterns["timeouts_s"] = "{:<8.8} ";
    formatPatterns["trunc"] = "{:<6.6} ";
    formatPatterns["type"] = "{:<6.6} ";
    formatPatterns["tickets"] = "{:<8.8} ";

    headers["active_connections"] = "ActConn";
    headers["failed_connections"] = "FailConn";
    headers["bytes"] = "Bytes";
    headers["bytes_s"] = "Bytes/s";
    headers["close"] = "Close";
    headers["close_s"] = "Close/s";
    headers["conn"] = "Conn";
    headers["conn_s"] = "Conn/s";
    headers["ctp95"] = "CTp95";
    headers["ctp99"] = "CTp99";
    headers["dir"] = "Dir";
    headers["domain"] = "Domain";
    headers["fin"] = "FIN";
    headers["fqdn"] = "Fqdn";
    headers["ip"] = "Ip";
    headers["mtu"] = "Mtu";
    headers["pkts"] = "Pkts";
    headers["pkts_s"] = "Pkts/s";
    headers["port"] = "Port";
    headers["proto"] = "Proto";
    headers["rcrd_rsp"] = "Rcrd/rsp";
    headers["top_client_ips"] = "TopClientIps";
    headers["req"] = "Req";
    headers["req_s"] = "Req/s";
    headers["rst"] = "RST";
    headers["srt"] = "Srt";
    headers["srt_s"] = "Srt/s";
    headers["srt95"] = "Srt95";
    headers["srt99"] = "Srt99";
    headers["srtMax"] = "SrtMax";

    headers["ds95"] = "Ds95";
    headers["ds99"] = "Ds99";
    headers["dsMax"] = "DsMax";

    headers["syn"] = "SYN";
    headers["synack"] = "SYNACK";
    headers["timeouts"] = "Tmo";
    headers["timeouts_s"] = "Tmo/s";
    headers["trunc"] = "Trunc";
    headers["type"] = "Type";
    headers["zwin"] = "0win";
    headers["tickets"] = "Tickets";
};

FlowFormatter::FlowFormatter(std::map<std::string, std::string>
                                 formatPatterns,
    std::map<std::string, std::string> headers,
    std::vector<std::string> displayKeys,
    std::vector<std::string> displayValues)
    : formatPatterns(std::move(std::move(formatPatterns)))
    , headers(std::move(std::move(headers)))
    , displayKeys(std::move(std::move(displayKeys)))
    , displayValues(std::move(std::move(displayValues)))
{
    FlowFormatter();
};

auto FlowFormatter::outputKey(std::map<std::string,
    std::string>& values) -> std::string
{
    fmt::memory_buffer keyBuf;
    for (auto& el : displayKeys) {
        fmt::format_to(keyBuf, formatPatterns[el], values[el]);
    }
    return to_string(keyBuf);
}

auto FlowFormatter::outputValue(std::map<std::string,
    std::string>& values) -> std::string
{
    fmt::memory_buffer valueBuf;
    for (auto& el : displayValues) {
        fmt::format_to(valueBuf, formatPatterns[el], values[el]);
    }
    return to_string(valueBuf);
}

void FlowFormatter::outputHeaders(std::string& keyHeaders,
    std::string& valueHeaders)
{
    keyHeaders = outputKey(headers);
    valueHeaders = outputValue(headers);
}

void FlowFormatter::setDisplayKeys(std::vector<std::string> const& keys)
{
    for (auto key : keys) {
        if (formatPatterns.find(key) == formatPatterns.end()) {
            spdlog::error("Could not find pattern for {}", key);
        }
    }
    displayKeys = keys;
}

void FlowFormatter::setDisplayValues(std::vector<std::string> const& values)
{
    for (auto key : values) {
        if (formatPatterns.find(key) == formatPatterns.end()) {
            spdlog::error("Could not find pattern for {}", key);
        }
    }

    displayValues = values;
}
} // namespace flowstats
