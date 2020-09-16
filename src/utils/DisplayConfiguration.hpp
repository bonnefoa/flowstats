#pragma once

#include "Field.hpp"
#include <string>
#include <vector>

namespace flowstats {

class DisplayConfiguration {
public:
    DisplayConfiguration();

    auto updateFieldSize(Field field, int delta) -> void;
    auto emptyFilter() { filter = ""; };
    auto addFilterChar(char c) { filter.push_back(c); };
    auto removeFilterChar() { filter.pop_back(); };
    auto toggleMergedDirection() { mergeDirection = !mergeDirection; };
    auto setMaxResults(int newMaxResults) {maxResults = newMaxResults;};

    [[nodiscard]] auto getFieldToSize() const& { return fieldToSize; };
    [[nodiscard]] auto getFilter() const& { return filter; };
    [[nodiscard]] auto getMaxResults() const { return maxResults; };
    [[nodiscard]] auto getMergeDirection() const { return mergeDirection; };
    [[nodiscard]] auto isFieldHidden(Field field) const -> bool;

private:
    std::vector<int> fieldToSize;
    std::string filter;
    bool mergeDirection = true;
    int maxResults = 1000;
};

} // namespace flowstats