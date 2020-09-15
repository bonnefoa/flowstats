#include "DisplayConfiguration.hpp"

namespace flowstats {

DisplayConfiguration::DisplayConfiguration()
{
    fieldToSize.resize(Field::_size());
    for (size_t i = 0; i < Field::_size(); ++i) {
        fieldToSize[i] = 8;
    }
    fieldToSize[Field::FQDN] = 42;

    fieldToSize[Field::TRUNC] = 6;
    fieldToSize[Field::TYPE] = 6;
    fieldToSize[Field::DIR] = 6;

    fieldToSize[Field::DOMAIN] = 34;

    fieldToSize[Field::BYTES] = 10;

    fieldToSize[Field::TOP_CLIENT_IPS] = 60;

    fieldToSize[Field::IP] = 16;

    fieldToSize[Field::PORT] = 5;
    fieldToSize[Field::PROTO] = 5;
}

auto DisplayConfiguration::isFieldHidden(Field field) const -> bool
{
    if (mergeDirection) {
        switch (field) {
            case Field::DIR: return true;
            default: return false;
        }
    }
    return false;
}

auto DisplayConfiguration::updateFieldSize(Field field, int delta) -> void
{
    auto& fieldSize = fieldToSize[field];
    fieldSize = std::max(fieldSize + delta, 0);
}

} // namespace flowstats
