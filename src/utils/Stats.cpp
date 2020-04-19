#include "Stats.hpp"
#include <algorithm>
#include <fmt/core.h> // for format

namespace flowstats {

void Percentile::merge()
{
    std::sort(points.begin(), points.end());
}

void Percentile::addPoint(uint32_t point)
{
    return points.push_back(point);
}

void Percentile::addPoints(Percentile& perc)
{
    points.insert(points.end(), perc.points.begin(), perc.points.end());
}

auto Percentile::getCount() -> int
{
    return points.size();
}

auto Percentile::getPercentile(float p) -> uint32_t
{
    if (points.size() == 0) {
        return 0;
}
    if (p == 0) {
        return points[0];
    }
    return points[int(points.size() * p + 0.5) - 1];
}

auto Percentile::getPercentileStr(float p) -> std::string
{
    if (points.size() == 0) {
        return "-";
}
    uint32_t res = getPercentile(p);
    return fmt::format("{}ms", res);
}

void Percentile::reset()
{
    points.clear();
}
}  // namespace flowstats
