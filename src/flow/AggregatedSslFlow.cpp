#include "AggregatedSslFlow.hpp"

namespace flowstats {

auto AggregatedSslFlow::fillValues(std::map<Field, std::string>& values,
    Direction direction) const -> void
{
    Flow::fillValues(values, direction);

    if (direction == FROM_CLIENT) {
        values[Field::FQDN] = getFqdn();
        values[Field::IP] = getSrvIp().to_string();
        values[Field::PORT] = std::to_string(getSrvPort());
        values[Field::DOMAIN] = domain;

        values[Field::CONN] = prettyFormatNumber(totalConnections);
        values[Field::CONN_RATE] = prettyFormatNumber(numConnections);
        values[Field::CT_P95] = connections.getPercentileStr(0.95);
        values[Field::CT_P99] = connections.getPercentileStr(0.99);
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

auto AggregatedSslFlow::addConnection(int delta) -> void
{
    connections.addPoint(delta);
    numConnections++;
    totalConnections++;
}

} // namespace flowstats
