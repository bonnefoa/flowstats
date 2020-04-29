#include "CollectorOutput.hpp"
#include <fmt/core.h>

namespace flowstats {

auto CollectorOutput::print() const -> void
{
    fmt::print("{} {}s\n", name, delta);
    for (int i = 0; i < keys.size(); ++i) {
        fmt::print("{} {}\n", keys[i], values[i]);
    }
    fmt::print("\n");
}
} // namespace flowstats
