#include "DisplayConfiguration.hpp"

namespace flowstats {

DisplayConfiguration::DisplayConfiguration()
{
    fieldToSize.resize(Field::_size());
    for (Field field : Field::_values()) {
        fieldToSize[field._to_index()] = fieldToInitialSize(field);
    }
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
