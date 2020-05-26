#pragma once
#include <fmt/format.h>
#include <pcap/pcap.h>
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

class CaptureStat {
public:
    CaptureStat() = default;
    CaptureStat(pcap_stat pcapStat)
        : recv(pcapStat.ps_recv)
        , drop(pcapStat.ps_drop)
        , ifDrop(pcapStat.ps_ifdrop) {};
    virtual ~CaptureStat() = default;

    [[nodiscard]] auto getRate(std::optional<CaptureStat> const& previousStat)
    {
        auto rateRecv = recv;
        auto rateDrop = drop;
        auto rateIfDrop = ifDrop;
        if (previousStat.has_value()) {
            rateRecv = recv - previousStat->recv;
            rateDrop = drop - previousStat->drop;
            rateIfDrop = ifDrop - previousStat->ifDrop;
        }
        auto rate = fmt::format("Packets recv:   {:>6}/s, drop: {:>4}/s, ifDrop: {:>4}/s\n",
            rateRecv, rateDrop, rateIfDrop);
        return rate;
    }

    [[nodiscard]] auto getTotal()
    {
        auto stats = fmt::format("Packets recv: {:>8}, drop: {:>6}, ifDrop: {:>6}\n",
            recv, drop, ifDrop);
        return stats;
    }

private:
    unsigned int recv = 0;
    unsigned int drop = 0;
    unsigned int ifDrop = 0;
};

} // namespace flowstats
