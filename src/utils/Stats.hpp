#pragma once
#include <string>
#include <vector>

namespace flowstats {
class Percentile {
public:
    Percentile() = default;
    virtual ~Percentile() = default;

    auto addPoint(uint32_t point) -> void;
    auto addPoints(Percentile const& perc) -> void;
    auto merge() -> void;
    auto reset() -> void;
    auto resetAndShrink() -> void;

    [[nodiscard]] auto getPercentile(float percentile) const -> uint32_t;
    [[nodiscard]] auto getPercentileStr(float p) const -> std::string;
    [[nodiscard]] auto getCount() const -> int;
    [[nodiscard]] auto getPoints() const -> std::vector<uint32_t> { return points; };

private:
    std::vector<uint32_t> points;
};
} // namespace flowstats
