#pragma once
#include <string>
#include <vector>

namespace flowstats {
class Percentile {
public:
    Percentile() {};
    virtual ~Percentile() {};

    void addPoint(uint32_t point);
    void addPoints(Percentile& perc);
    void merge();
    uint32_t getPercentile(float percentile);
    std::string getPercentileStr(float p);
    int getCount();
    void reset();
    std::vector<uint32_t> getPoints() { return points; };

private:
    std::vector<uint32_t> points;
};
}
