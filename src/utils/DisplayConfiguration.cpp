#include "DisplayConfiguration.hpp"

namespace flowstats {

DisplayConfiguration::DisplayConfiguration()
{
    fieldToSize.resize(Field::_size());
    for (size_t i = 0; i < Field::_size(); ++i) {
        fieldToSize[i] = 12;
    }
    fieldToSize[Field::FQDN] = 42;

    fieldToSize[Field::TRUNC] = 6;
    fieldToSize[Field::TYPE] = 6;
    fieldToSize[Field::DIR] = 6;

    fieldToSize[Field::DOMAIN] = 34;
    fieldToSize[Field::CIPHER_SUITE] = 38;

    fieldToSize[Field::BYTES] = 12;

    fieldToSize[Field::TOP_CLIENT_IPS_IP] = 24;
    fieldToSize[Field::TOP_CLIENT_IPS_PKTS] = 18;
    fieldToSize[Field::TOP_CLIENT_IPS_BYTES] = 18;
    fieldToSize[Field::TOP_CLIENT_IPS_REQUESTS] = 18;

    fieldToSize[Field::IP] = 16;

    fieldToSize[Field::PORT] = 5;
    fieldToSize[Field::PROTO] = 5;
}

auto DisplayConfiguration::updateFieldSize(Field field, int delta) -> void
{
    auto& fieldSize = fieldToSize[field];
    fieldSize = std::max(fieldSize + delta, 0);
}

auto DisplayConfiguration::nextRateMode() -> void
{
    auto index = rateMode._to_index();
    if (index == RateMode::_size() - 1) {
        return;
    }
    rateMode = RateMode::_from_index(index + 1);
};

auto DisplayConfiguration::previousRateMode() -> void
{
    auto index = rateMode._to_index();
    if (index == 0) {
        return;
    }
    rateMode = RateMode::_from_index(index - 1);
}

} // namespace flowstats
