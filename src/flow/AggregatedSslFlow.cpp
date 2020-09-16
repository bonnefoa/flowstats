#include "AggregatedSslFlow.hpp"

namespace flowstats {

auto AggregatedSslFlow::getFieldStr(Field field, Direction direction, int duration) const -> std::string
{
    auto fqdn = getFqdn();
    if (fqdn == "Total") {
        if (direction != FROM_SERVER) {
            switch (field) {
                case Field::FQDN: return getFqdn();
                default:
                                  break;
            }
        }
    } else if (direction == FROM_CLIENT || direction == MERGED) {
        switch (field) {
            case Field::FQDN: return getFqdn();
            case Field::IP: return getSrvIp();
            case Field::PORT: return std::to_string(getSrvPort());
            case Field::DOMAIN: return domain;
            case Field::TLS_VERSION: return tlsVersion._to_string();
            case Field::CIPHER_SUITE: {
                if (!sslCipherSuite) {
                    return "Unknown";
                }
                return sslCipherSuite->_to_string();
            }

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

auto AggregatedSslFlow::setTlsVersion(TLSVersion tlsVers) -> void
{
    tlsVersion = tlsVers;
}

auto AggregatedSslFlow::addConnection(int delta) -> void
{
    connections.addPoint(delta);
    numConnections++;
    totalConnections++;
}

} // namespace flowstats
