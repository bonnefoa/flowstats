#pragma once

#include "Flow.hpp"
#include "Utils.hpp"
#include <fmt/format.h>
#include <map>

namespace flowstats {

class AggregatedKey {
public:
    explicit AggregatedKey(std::string fqdn)
        : fqdn(std::move(fqdn)) {};
    virtual ~AggregatedKey() = default;
    auto operator<(AggregatedKey const& b) const -> bool
    {
        return fqdn < b.fqdn;
    }

    [[nodiscard]] auto getFqdn() const { return fqdn; }

private:
    std::string fqdn;
};

} // namespace flowstats
