#pragma once
#include <string>
#include <vector>

namespace flowstats {
class Percentile {
public:
    Percentile() {};
    virtual ~Percentile() = default;

    auto addPoint(uint32_t point) -> void;
    auto addPoints(Percentile const& perc) -> void;
    auto merge() -> void;
    auto getPercentile(float percentile) -> uint32_t;
    auto getPercentileStr(float p) -> std::string;
    auto getCount() -> int;
    auto reset() -> void;
    auto getPoints() -> std::vector<uint32_t> { return points; };

private:
    std::vector<uint32_t> points;
};
}
