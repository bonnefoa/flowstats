#include "AggregatedSslFlow.hpp"

namespace flowstats {

auto AggregatedSslFlow::fillValues(std::map<std::string, std::string>& values,
    Direction direction, int duration) const -> void
{
    Flow::fillValues(values, direction, duration);

    if (direction == FROM_CLIENT) {
        values["fqdn"] = fqdn;
        values["ip"] = getSrvIp().to_string();
        values["port"] = std::to_string(getSrvPort());
        values["domain"] = domain;

        values["conn"] = prettyFormatNumber(totalConnections);
        values["conn_s"] = prettyFormatNumber(numConnections);
        values["ctp95"] = connections.getPercentileStr(0.95);
        values["ctp99"] = connections.getPercentileStr(0.99);
    }
}

void AggregatedSslFlow::resetFlow(bool resetTotal)
{
    Flow::resetFlow(resetTotal);
    connections.reset();
    numConnections = 0;

    if (resetTotal) {
        totalConnections = 0;
    }
}
} // namespace flowstats
