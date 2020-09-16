#include "AggregatedSslFlow.hpp"

namespace flowstats {

auto AggregatedSslFlow::getFieldStr(Field field, Direction direction, int duration) const -> std::string
{
    if (direction == FROM_CLIENT || direction == MERGED) {
        switch (field) {
            case Field::FQDN: return getFqdn();
            case Field::IP: return getSrvIp();
            case Field::PORT: return std::to_string(getSrvPort());
            case Field::DOMAIN: return domain;
            case Field::TLS_VERSION: return tlsVersion._to_string();

            case Field::CONN: return prettyFormatNumber(totalConnections);
            case Field::CONN_RATE: return prettyFormatNumber(numConnections);
            case Field::CT_P95: return connections.getPercentileStr(0.95);
            case Field::CT_P99: return connections.getPercentileStr(0.99);
            default: break;
        }
    }
    return Flow::getFieldStr(field, direction, duration);
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

auto AggregatedSslFlow::addConnection(int delta, TLSVersion tlsVers) -> void
{
    connections.addPoint(delta);
    if (tlsVersion == +TLSVersion::UNKNOWN) {
        tlsVersion = tlsVers;
    }
    numConnections++;
    totalConnections++;
}

} // namespace flowstats
