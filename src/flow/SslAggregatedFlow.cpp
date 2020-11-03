#include "SslAggregatedFlow.hpp"

namespace flowstats {

auto SslAggregatedFlow::getFieldStr(Field field, Direction direction, int duration, int index) const -> std::string
{
    auto fqdn = getFqdn();
    if (fqdn == "Total") {
        if (direction == FROM_CLIENT || direction == MERGED) {
            switch (field) {
                case Field::PORT:
                case Field::DOMAIN:
                case Field::TLS_VERSION:
                case Field::CIPHER_SUITE:
                    return "-";
                default:
                    break;
            }
        }
    }

    if (direction == FROM_CLIENT || direction == MERGED) {
        switch (field) {
            case Field::FQDN: return getFqdn();
            case Field::IP: return getSrvIp().getAddrStr();
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
            case Field::CONN_AVG: return prettyFormatNumberAverage(totalConnections, duration);
            case Field::CT_P95: return connectionTimes.getPercentileStr(0.95);
            case Field::CT_P99: return connectionTimes.getPercentileStr(0.99);
            case Field::CT_TOTAL_P95: return totalConnectionTimes.getPercentileStr(0.95);
            case Field::CT_TOTAL_P99: return totalConnectionTimes.getPercentileStr(0.99);
            default: break;
        }
    }
    return Flow::getFieldStr(field, direction, duration, index);
}

void SslAggregatedFlow::resetFlow(bool resetTotal)
{
    Flow::resetFlow(resetTotal);
    connectionTimes.reset();
    numConnections = 0;

    if (resetTotal) {
        totalConnections = 0;
        totalConnectionTimes.reset();
    }
}

auto SslAggregatedFlow::setTlsVersion(TLSVersion tlsVers) -> void
{
    tlsVersion = tlsVers;
}

auto SslAggregatedFlow::addConnection(int delta) -> void
{
    connectionTimes.addPoint(delta);
    totalConnectionTimes.addPoint(delta);
    numConnections++;
    totalConnections++;
}

} // namespace flowstats
