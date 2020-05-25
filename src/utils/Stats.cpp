#include "Stats.hpp"
#include <algorithm>
#include <cmath>
#include <fmt/core.h> // for format

namespace flowstats {

auto Percentile::merge() -> void
{
    std::sort(points.begin(), points.end());
}

auto Percentile::addPoint(uint32_t point) -> void
{
    return points.push_back(point);
}

auto Percentile::addPoints(Percentile const& perc) -> void
{
    points.insert(points.end(), perc.points.begin(), perc.points.end());
}

auto Percentile::getCount() const -> int
{
    return points.size();
}

auto Percentile::getPercentile(float p) const -> uint32_t
{
    if (points.size() == 0) {
        return 0;
    }
    if (p == 0) {
        return points[0];
    }
    return points[floor(points.size() * p + 0.5) - 1];
}

auto Percentile::getPercentileStr(float p) const -> std::string
{
    if (points.size() == 0) {
        return "-";
    }
    uint32_t res = getPercentile(p);
    return fmt::format("{}ms", res);
}

auto Percentile::reset() -> void
{
    points.clear();
}

auto Percentile::resetAndShrink() -> void
{
    points.clear();
    points.shrink_to_fit();
}
} // namespace flowstats
