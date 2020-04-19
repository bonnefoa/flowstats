#include "CollectorOutput.hpp"
#include <fmt/core.h>

namespace flowstats {

void CollectorOutput::print()
{
    for (int i = 0; i < keys.size(); ++i) {
        fmt::print("{} {}\n", keys[i], values[i]);
    }
    fmt::print("\n");
}
} // namespace flowstats
