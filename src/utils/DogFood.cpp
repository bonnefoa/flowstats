#include "DogFood.hpp"
#include "Utils.hpp"

namespace DogFood {

auto DefaultConfiguration() -> Configuration
{
    return std::make_tuple(
        Mode::UDP,
        std::string(DOGSTATSD_HOST),
        static_cast<int>(DOGSTATSD_PORT));
}

#if defined(_DOGFOOD_UDS_SUPPORT)
auto UDS(const std::string& _path) -> Configuration
{
    return std::make_tuple(Mode::UDS, _path, -1);
}
#endif

auto UDP(const std::string& _host, const int _port) -> Configuration
{
    return std::make_tuple(Mode::UDP, _host, _port);
}

auto Configure(
    const Mode& _mode,
    const std::string& _host,
    const int _port) -> Configuration
{
    return std::make_tuple(_mode, _host, _port);
}

auto Configure(const std::string& path) -> std::optional<Configuration>
{
    if (path.empty()) {
        SPDLOG_INFO("No agent configuration found, no metrics will be send");
        return {};
    }
    if (path[0] == '/') {
#if defined(_DOGFOOD_UDS_SUPPORT)
        SPDLOG_INFO("Configuring agent with UDS path {}", path);
        return UDS(path);
#else
        SPDLOG_INFO("No UDS on this system, no metrics will be send");
        return {};
#endif
    }
    std::vector<std::string> tokens = flowstats::split(path, ':');
    if (tokens.size() != 2) {
        SPDLOG_INFO("Invalid datadog agent path {}", path);
        return {};
    }
    SPDLOG_INFO("Configuring agent with host {} and port {}", tokens[0], tokens[1]);
    return UDP(tokens[0], stoi(tokens[1]));
}

auto Tag(
    const std::string& key,
    const std::string& value = "") -> std::pair<std::string, std::string>
{
    return std::make_pair(key, value);
}

////////////////////////////////////////////////////////////////
// ValidateTagName
//
//     - Must not be empty or longer than 200 characters
//     - Must start with a letter
//     - Must not end with a colon
//     - Must contain only:
//         - Alphanumerics
//         - Underscores
//         - Minuses
//         - Colons
//         - Periods
//         - Slashes
//     - Other special characters get converted to underscores.
//
inline auto ValidateTags(const std::string& _tag) -> bool
{
#if defined(_DOGFOOD_UNSAFE_NAMES)
    ////////////////////////////////////////////////////////
    // Support unsafe names
    return true;
#else
    ////////////////////////////////////////////////////////
    // Use explicit name checking

    ////////////////////////////////////////////////////////
    // Verify the length
    if (_tag.length() == 0 || _tag.length() > 200) {
        return false;
    }

    ////////////////////////////////////////////////////////
    // Verify the first character is a letter
    if (!std::isalpha(_tag.at(0))) {
        return false;
    }

    ////////////////////////////////////////////////////////
    // Verify end is not a colon
    if (_tag.back() == ':') {
        return false;
    }

    ////////////////////////////////////////////////////////
    // Verify each character
    for (char c : _tag) {
        if (std::isalnum(c) || c == '_' || c == '-' || c == ':' || c == '.' || c == '/' || c == '\\') {
            continue;
        } else {
            return false;
        }
    }

    return true;
#endif
}

////////////////////////////////////////////////////////////////
// ExtractTags
//
//     Return a string modeling a tags object
//
inline auto ExtractTags(const Tags& _tags) -> std::string
{
    ////////////////////////////////////////////////////////////
    // The tags string to build up
    std::string stream;

    ////////////////////////////////////////////////////////////
    // Check for the presence of tags
    if (_tags.size() > 0) {
        stream += "|#";
    }

    ////////////////////////////////////////////////////////
    // Tag buffer
    std::string _tag = "";

    ////////////////////////////////////////////////////////////
    // Add each tag
    for (const auto& p : _tags) {
        ////////////////////////////////////////////////////////
        // Clear the tag buffer
        _tag.clear();

        ////////////////////////////////////////////////////////
        // If the 'Key' is not empty
        if (p.first.size() > 0) {
            ////////////////////////////////////////////////////
            // Append the 'Key'
            _tag += p.first;

            ////////////////////////////////////////////////////
            // If the 'Value' is not empty, append after a colon
            if (p.second.size() > 0) {
                _tag += (":" + p.second);
            }

            ////////////////////////////////////////////////////
            // Validate the tag
            if (!ValidateTags(_tag)) {
                continue;
            }

            ////////////////////////////////////////////////////
            // Append the tag and a comma for the next key-value
            stream += (_tag + ",");
        }
    }

    ////////////////////////////////////////////////////////////
    // Remove the trailing comma if present
    //     I really dislike 'if' statements to check boundary
    //     conditions in loops.
    if (stream.size() > 0 && stream.back() == ',') {
        stream.pop_back();
    }

    return stream;
}

////////////////////////////////////////////////////////////////
// ValidateMetricName
//
//     - Must not be empty or longer than 200 characters
//     - Must start with a letter
//     - Must not contain '|', ':', or '@'
//
inline auto ValidateMetricName(const std::string& _name) -> bool
{
#if defined(_DOGFOOD_UNSAFE_NAMES)
    ////////////////////////////////////////////////////////
    // Support unsafe names
    return true;
#else
    ////////////////////////////////////////////////////////
    // Use explicit name checking

    ////////////////////////////////////////////////////////
    // Verify the length
    if (_name.length() == 0 || _name.length() > 200) {
        return false;
    }

    ////////////////////////////////////////////////////////
    // Verify the first character is a letter
    if (!std::isalpha(_name.at(0))) {
        return false;
    }

    ////////////////////////////////////////////////////////
    // Verify each character
    for (char c : _name) {
        if (std::isalnum(c) || c == '_' || c == '.') {
            continue;
        } else {
            return false;
        }
    }

    return true;
#endif
}

////////////////////////////////////////////////////////////////
// ValidateSampleRate
//
//     Must be between 0.0 and 1.0 (inclusive)
//
inline auto ValidateSampleRate(const double _rate) -> bool
{
    return _rate >= 0.0 && _rate <= 1.0;
}

////////////////////////////////////////////////////////////////
// ValidateType
//
//     Must be a valid DataDog metric type
//
inline auto ValidateType(const Type& _type) -> bool
{
    switch (_type) {
        case Type::Counter:
        case Type::Gauge:
        case Type::Timer:
        case Type::Histogram:
        case Type::Set:
            return true;
        default:
            return false;
    }
}

////////////////////////////////////////////////////////////////
// EscapeEventText
//
//     Insert line breaks with an escaped slash (\\n)
//
inline auto EscapeEventText(const std::string& _text) -> std::string
{
    ////////////////////////////////////////////////////////////
    // Iterate through input string searching for '\n'
    std::string buffer;
    for (const char c : _text) {
        ////////////////////////////////////////////////////////
        // Replace newline literals with '\\n'
        if (c == '\n') {
            buffer.append("\\n");
        } else {
            buffer.push_back(c);
        }
    }
    return buffer;
}

////////////////////////////////////////////////////////////////
// ValidatePayloadSize
//
//     - Must be less than 65,507 bytes (inclusive)
//     - 65,507 = 65,535 − 8 (UDP header) − 20 (IP header)
//
inline auto ValidatePayloadSize(const std::string& _payload) -> bool
{
    return _payload.size() <= 65507;
}

// Default to calling std::to_string
template <typename ValueType>
auto value_to_string(
    const ValueType& _value) -> std::string
{
    return std::to_string(_value);
}

// Specialize std::string to identity
template <>
auto value_to_string<std::string>(
    const std::string& _value) -> std::string
{
    return _value;
}

auto Metric(
    const std::string& _name,
    const double _value,
    const Type _type,
    const double _rate,
    const Tags& _tags)
    _DOGFOOD_NOEXCEPT -> std::string
{
    ////////////////////////////////////////////////////////////
    // Declare the datagram stream
    std::string _datagram;

    ////////////////////////////////////////////////////////////
    // Validate the name
    if (!ValidateMetricName(_name)) {
        return "";
    }

    ////////////////////////////////////////////////////////////
    // Verify the rate
    //
    //     - Must be between 0.0 and 1.0 (inclusive)
    //
    if (!ValidateSampleRate(_rate)) {
        return "";
    }

    ////////////////////////////////////////////////////////////
    // Add the name and the numeric to the datagram
    //
    //     `metric.name:value|`
    //
    _datagram += _name + ":" + value_to_string(_value) + "|";

    ////////////////////////////////////////////////////////////
    // Verify the type and append the datagram
    //
    //     `c` or `g` or `ms` or `h` or `s`
    //
    switch (_type) {
        case Type::Counter:
            _datagram += "c";
            break;
        case Type::Gauge:
            _datagram += "g";
            break;
        case Type::Timer:
            _datagram += "ms";
            break;
        case Type::Histogram:
            _datagram += "h";
            break;
        case Type::Set:
            _datagram += "s";
            break;
        default:
            return "";
    }

    ////////////////////////////////////////////////////////////
    // Add the rate to the datagram if present
    //
    //     `|@sample_rate`
    //
    if (_rate != 1.0) {
        _datagram += "|@" + std::to_string(_rate);
    }

    ////////////////////////////////////////////////////////////
    // Extract the tags string into the datagram if present
    //
    //     `|#tag1:value,tag2`
    //
    _datagram += ExtractTags(_tags);

    ////////////////////////////////////////////////////////////
    // Validate the payload size
    if (!ValidatePayloadSize(_datagram)) {
        return "";
    }

    return _datagram;
}

////////////////////////////////////////////////////////////////
// ValidatePort
//
//     - An unsigned 16 bit integer
//
inline auto ValidatePort(const int _port) -> bool
{
    return _port > 0 && _port <= 65535;
}

auto Send(
    const std::string& _datagram,
    const Configuration& _configuration) -> bool
{
    Mode _mode = std::get<0>(_configuration);
    const std::string& _path = std::get<1>(_configuration);
    int _port = std::get<2>(_configuration);

    if (_mode == Mode::UDP) {
        if (!ValidatePort(_port)) {
            return false;
        }

        UDP_SEND_DATAGRAM(
            _datagram.data(),
            _datagram.size(),
            _path.c_str(),
            _port);
    }
#if defined(_DOGFOOD_UDS_SUPPORT)
    else if (_mode == Mode::UDS) {
        UDS_SEND_DATAGRAM(
            _datagram.data(),
            _datagram.size(),
            _path.c_str());
    }
#endif

    return true;
}

} // namespace DogFood
