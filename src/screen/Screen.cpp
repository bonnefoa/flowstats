#include "Screen.hpp"
#include "Utils.hpp"
#include <fmt/format.h>
#include <tins/dns.h>
#include <tins/tcp.h>
#include <utility>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define CTRL(x) ((x)&0x1f)

#define KEY_ESC 27
#define KEY_INF 60
#define KEY_SUP 62
#define KEY_B 98
#define KEY_LETTER_F 102
#define KEY_P 112
#define KEY_Q 113
#define KEY_R 114
#define KEY_S 115
#define KEY_VALID '\n'

#define KEY_0 48
#define KEY_NUM(n) (KEY_0 + (n))

// Sizes
#define STATUS_LINES 5
#define STATUS_COLUMNS 120

#define HEADER_LINES 1

#define KEY_LINES 300
#define KEY_COLUMNS 89

#define VALUE_LINES 300
#define VALUE_COLUMNS 100

#define MENU_LINES 1
#define MENU_COLUMNS 120

#define SORT_LINES 300
#define SORT_TEXT_COLUMNS 19
#define SORT_COLUMNS 20

// Colors
#define SELECTED_STATUS_COLOR 1
#define SELECTED_LINE_COLOR 2
#define MENU_COLOR 3
#define SELECTED_VALUE_COLOR 4
#define KEY_HEADER_COLOR 5
#define VALUE_HEADER_COLOR 6

namespace flowstats {

int lastKey = 0;
std::array<CollectorProtocol, 3> protocols = { CollectorProtocol::DNS, CollectorProtocol::TCP, CollectorProtocol::SSL };
std::array<int, 3> protocolToDisplayIndex = { 0, 0, 0 };
std::array<int, 3> protocolToSortIndex = { 0, 0, 0 };

auto Screen::updateDisplay(timeval tv, bool updateOutput,
    std::optional<CaptureStat> const& captureStat) -> void
{
    if (displayConf->noCurses) {
        return;
    }
    if (firstTv.tv_sec == 0) {
        firstTv = tv;
    }
    lastTv = tv;

    const std::lock_guard<std::mutex> lock(screenMutex);
    updateStatus(captureStat);
    updateSortSelection();
    updateMenu();

    if (shouldFreeze == true) {
        refreshPads();
        return;
    }

    if (updateOutput) {
        collectorOutput = activeCollector->outputStatus(tv.tv_sec - firstTv.tv_sec);
    }

    updateHeaders();
    updateValues();

    refreshPads();
}

auto Screen::updateValues() -> void
{
    werase(keyWin);
    werase(valueWin);


    auto numKeys = collectorOutput.getKeys().size();
    numberElements = int(numKeys / 2);
    for (int i = 0; i < numKeys; ++i) {
        int line = i / 2;
        if (line == selectedLine) {
            wattron(keyWin, COLOR_PAIR(SELECTED_LINE_COLOR));
            wattron(valueWin, COLOR_PAIR(SELECTED_LINE_COLOR));
        }
        mvwprintw(keyWin, i, 0,
            fmt::format("{:<" STR(KEY_COLUMNS) "}",
                collectorOutput.getKeys()[i].c_str())
                .c_str());
        mvwprintw(valueWin, i, 0,
            fmt::format("{:<" STR(VALUE_COLUMNS) "}",
                collectorOutput.getValues()[i].c_str())
                .c_str());
        if (line == selectedLine) {
            wattroff(keyWin, COLOR_PAIR(SELECTED_LINE_COLOR));
            wattroff(valueWin, COLOR_PAIR(SELECTED_LINE_COLOR));
        }
    }
}

auto Screen::updateSortSelection() -> void
{
    if (editSort == false) {
        return;
    }
    werase(sortSelectionWin);
    wattron(sortSelectionWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(sortSelectionWin, fmt::format("{:<" STR(SORT_TEXT_COLUMNS) "}", "Sort by").c_str());
    wattroff(sortSelectionWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(sortSelectionWin, " ");

    int i = 0;
    int displayIndex = protocolToSortIndex[displayConf->protocolIndex];
    for (const auto& sortField : activeCollector->getSortFields()) {
        if (i == displayIndex) {
            wattron(sortSelectionWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        waddstr(sortSelectionWin, fmt::format("{:<" STR(SORT_TEXT_COLUMNS) "}", fieldToHeader(sortField)).c_str());
        if (i == displayIndex) {
            wattroff(sortSelectionWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        i++;
        waddstr(sortSelectionWin, "\n");
    }
}

auto Screen::updateStatus(std::optional<CaptureStat> const& captureStat) -> void
{
    werase(statusWin);
    waddstr(statusWin, fmt::format("Running time: {}s\n", lastTv.tv_sec - firstTv.tv_sec).c_str());

    if (captureStat.has_value()) {
        stagingCaptureStat = captureStat.value();
    }

    auto previousUpdateMs = timevalInMs(lastCaptureStatUpdate);
    auto lastTsMs = timevalInMs(lastTv);
    if (lastTsMs > previousUpdateMs && lastTsMs - previousUpdateMs > 1000) {
        previousCaptureStat = currentCaptureStat;
        currentCaptureStat = stagingCaptureStat;
        lastCaptureStatUpdate = lastTv;
    }

    waddstr(statusWin, currentCaptureStat.getTotal().c_str());
    waddstr(statusWin, currentCaptureStat.getRate(previousCaptureStat).c_str());

    waddstr(statusWin, fmt::format("{:<10} ", "Protocol:").c_str());
    for (int i = 0; i < ARRAY_SIZE(protocols); ++i) {
        auto proto = protocols[i];
        if (displayConf->protocolIndex == i) {
            wattron(statusWin, COLOR_PAIR(SELECTED_STATUS_COLOR));
        }
        waddstr(statusWin, fmt::format("{}: {:<10} ", i + 1, proto._to_string()).c_str());
        if (displayConf->protocolIndex == i) {
            wattroff(statusWin, COLOR_PAIR(SELECTED_STATUS_COLOR));
        }
    }
    waddstr(statusWin, "\n");

    waddstr(statusWin, fmt::format("{:<10} ", "Display:").c_str());
    int i = 0;
    int displayIndex = protocolToDisplayIndex[displayConf->protocolIndex];
    for (const auto& displayPair : activeCollector->getDisplayPairs()) {
        if (i == displayIndex) {
            wattron(statusWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        waddstr(statusWin, fmt::format("{:<14}", displayTypeToString(displayPair.first)).c_str());
        if (i == displayIndex) {
            wattroff(statusWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        i++;
    }
    waddstr(statusWin, "\n");
}

auto Screen::updateHeaders() -> void
{
    werase(keyHeaderWin);
    werase(valueHeaderWin);

    wattron(keyHeaderWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(keyHeaderWin, fmt::format("{:<" STR(KEY_COLUMNS) "}", collectorOutput.getKeyHeaders()).c_str());
    wattroff(keyHeaderWin, COLOR_PAIR(KEY_HEADER_COLOR));

    wattron(valueHeaderWin, COLOR_PAIR(VALUE_HEADER_COLOR));
    waddstr(valueHeaderWin, fmt::format("{:<" STR(VALUE_COLUMNS) "}", collectorOutput.getValueHeaders()).c_str());
    wattroff(valueHeaderWin, COLOR_PAIR(VALUE_HEADER_COLOR));
}

auto Screen::updateMenu() -> void
{
    werase(menuWin);

    if (editFilter || editSort) {
        waddstr(menuWin, "Enter: ");
        wattron(menuWin, COLOR_PAIR(MENU_COLOR));
        waddstr(menuWin, fmt::format("{:<6}", "Done").c_str());
        wattroff(menuWin, COLOR_PAIR(MENU_COLOR));

        waddstr(menuWin, "Esc: ");
        wattron(menuWin, COLOR_PAIR(MENU_COLOR));
        waddstr(menuWin, fmt::format("{:<6}", "Clear").c_str());
        wattroff(menuWin, COLOR_PAIR(MENU_COLOR));

        waddstr(menuWin, " ");
    } else {
        waddstr(menuWin, "F4 ");
        wattron(menuWin, COLOR_PAIR(MENU_COLOR));
        waddstr(menuWin, fmt::format("{:<6}", "Filter").c_str());
        wattroff(menuWin, COLOR_PAIR(MENU_COLOR));
    }

    if (editFilter) {
        wattron(menuWin, COLOR_PAIR(MENU_COLOR));
        waddstr(menuWin, fmt::format("Filter: {}", displayConf->filter).c_str());
        wattroff(menuWin, COLOR_PAIR(MENU_COLOR));
    }
}

auto Screen::getActiveCollector() -> Collector*
{
    for (auto& collector : collectors) {
        if (protocols[displayConf->protocolIndex] != collector->getProtocol()) {
            continue;
        }
        return collector;
    }
    return nullptr;
}

Screen::Screen(std::atomic_bool* shouldStop,
    DisplayConfiguration* displayConf,
    std::vector<Collector*> collectors)
    : shouldStop(shouldStop)
    , displayConf(displayConf)
    , collectors(std::move(std::move(collectors)))
{
    if (displayConf->noCurses) {
        return;
    }
    initscr();

    use_default_colors();
    start_color();

    init_pair(SELECTED_STATUS_COLOR, COLOR_BLACK, COLOR_WHITE);
    init_pair(SELECTED_LINE_COLOR, COLOR_BLACK, COLOR_CYAN);

    init_pair(MENU_COLOR, COLOR_BLACK, COLOR_CYAN);
    init_pair(KEY_HEADER_COLOR, COLOR_BLACK, COLOR_GREEN);
    init_pair(SELECTED_VALUE_COLOR, COLOR_BLACK, COLOR_WHITE);
    init_pair(VALUE_HEADER_COLOR, COLOR_BLACK, COLOR_GREEN);

    keypad(stdscr, true);
    cbreak();
    noecho();
    curs_set(0);
    set_escdelay(25);
    timeout(100);

    keyWin = newpad(KEY_LINES, KEY_COLUMNS);
    valueWin = newpad(VALUE_LINES, VALUE_COLUMNS);
    keyHeaderWin = newpad(HEADER_LINES + STATUS_LINES, KEY_COLUMNS);
    valueHeaderWin = newpad(HEADER_LINES + STATUS_LINES, VALUE_COLUMNS);

    statusWin = newwin(STATUS_LINES, STATUS_COLUMNS, 0, 0);
    sortSelectionWin = newwin(SORT_LINES, SORT_COLUMNS,
        STATUS_LINES, 0);
    menuWin = newwin(MENU_LINES, MENU_COLUMNS, LINES - 1, 0);

    activeCollector = getActiveCollector();
}

auto Screen::refreshPads() -> void
{
    if (displayConf->noDisplay) {
        return;
    }
    wnoutrefresh(statusWin);

    int deltaValues = 0;
    if (editSort) {
        deltaValues = SORT_COLUMNS;
        wnoutrefresh(sortSelectionWin);
    }

    pnoutrefresh(keyHeaderWin,
        0, 0,
        STATUS_LINES, deltaValues,
        STATUS_LINES + HEADER_LINES, KEY_COLUMNS + deltaValues);

    pnoutrefresh(keyWin,
        verticalScroll, 0,
        STATUS_LINES + HEADER_LINES, deltaValues,
        LINES - (HEADER_LINES + MENU_LINES), KEY_COLUMNS + deltaValues);

    pnoutrefresh(valueHeaderWin,
        0, 0,
        STATUS_LINES, KEY_COLUMNS + deltaValues,
        STATUS_LINES + HEADER_LINES, COLS - deltaValues - 1);

    pnoutrefresh(valueWin,
        verticalScroll, 0,
        STATUS_LINES + HEADER_LINES, KEY_COLUMNS + deltaValues,
        LINES - (HEADER_LINES + MENU_LINES), COLS - deltaValues - 1);

    wnoutrefresh(menuWin);
    doupdate();
}

auto Screen::refreshableAction(int c) -> bool
{
    if (editFilter) {
        if (c == KEY_ESC) {
            nodelay(stdscr, true);
            c = getch();
            nodelay(stdscr, false);
            if (c == -1) {
                displayConf->filter = "";
                editFilter = false;
            }
        } else if (c == CTRL('u')) {
            displayConf->filter = "";
        } else if (c == KEY_VALID) {
            editFilter = false;
        } else if (c == KEY_BACKSPACE && displayConf->filter.size() > 0) {
            displayConf->filter.pop_back();
        } else if (isprint(c)) {
            displayConf->filter.push_back(c);
        } else {
            return false;
        }
        return true;
    }

    if (editSort) {
        if (c == KEY_UP) {
            protocolToSortIndex[displayConf->protocolIndex] = std::max(
                protocolToSortIndex[displayConf->protocolIndex] - 1, 0);
            activeCollector->updateSort(protocolToSortIndex[displayConf->protocolIndex], reversedSort);
            return true;
        } else if (c == KEY_DOWN) {
            protocolToSortIndex[displayConf->protocolIndex] = std::min(
                protocolToSortIndex[displayConf->protocolIndex] + 1,
                static_cast<int>(activeCollector->getSortFields().size()) - 1);
            activeCollector->updateSort(protocolToSortIndex[displayConf->protocolIndex], reversedSort);
            return true;
        } else if (c == KEY_VALID) {
            editSort = false;
            return true;
        }
    }

    if (c >= KEY_NUM(1) && c <= KEY_NUM(3)) {
        displayConf->protocolIndex = c - KEY_NUM(1);
        activeCollector = getActiveCollector();
        return true;
    } else if (c == KEY_F(4)) {
        editFilter = true;
        return true;
    } else if (c == KEY_LEFT) {
        protocolToDisplayIndex[displayConf->protocolIndex] = std::max(
            protocolToDisplayIndex[displayConf->protocolIndex] - 1, 0);
        activeCollector->updateDisplayType(protocolToDisplayIndex[displayConf->protocolIndex]);
        return true;
    } else if (c == KEY_RIGHT) {
        protocolToDisplayIndex[displayConf->protocolIndex] = std::min(
            protocolToDisplayIndex[displayConf->protocolIndex] + 1,
            static_cast<int>(activeCollector->getDisplayPairs().size()) - 1);
        activeCollector->updateDisplayType(protocolToDisplayIndex[displayConf->protocolIndex]);
        return true;
    } else if (c == KEY_SUP) {
        editSort = true;
        reversedSort = false;
        activeCollector->updateSort(protocolToSortIndex[displayConf->protocolIndex], reversedSort);
        return true;
    } else if (c == KEY_INF) {
        editSort = true;
        reversedSort = true;
        activeCollector->updateSort(protocolToSortIndex[displayConf->protocolIndex], reversedSort);
        return true;
    }

    return false;
}

auto Screen::displayLoop() -> void
{
    int c;
    while (shouldStop->load() == false) {

        c = getch();
        if (c == ERR) {
            if (displayConf->pcapReplay) {
                continue;
            }
            struct timeval currentTime = {};
            gettimeofday(&currentTime, nullptr);
            if (getTimevalDeltaMs(lastTv, currentTime) > 1000) {
                updateDisplay(currentTime, true, {});
            }
            continue;
        }
        lastKey = c;
        if (c == KEY_Q || c == CTRL('c')) {
            shouldStop->store(true);
            return;
        }

        if (refreshableAction(c)) {
            updateDisplay(lastTv, true, {});
            continue;
        }

        maxElements = (LINES - (STATUS_LINES + HEADER_LINES + MENU_LINES)) / 2 - 1;
        switch (c) {
        case KEY_LETTER_F:
            shouldFreeze = !shouldFreeze;
            break;
        case KEY_UP:
            selectedLine -= 1;
            selectedLine = std::max(selectedLine, 0);
            break;
        case KEY_DOWN:
            selectedLine += 1;
            selectedLine = std::min(selectedLine, numberElements - 1);
            break;
        case KEY_PPAGE:
            selectedLine -= maxElements;
            selectedLine = std::max(selectedLine, 0);
            break;
        case KEY_NPAGE:
            selectedLine += maxElements;
            selectedLine = std::min(selectedLine, numberElements - 1);
            break;
        }
        if (selectedLine * 2 < verticalScroll) {
            verticalScroll = selectedLine * 2;
        } else if (selectedLine * 2 > (maxElements * 2 + verticalScroll)) {
            verticalScroll += selectedLine * 2 - (maxElements * 2 + verticalScroll);
        }
        updateDisplay(lastTv, false, {});
    }
}

auto Screen::StartDisplay() -> int
{
    if (displayConf->noCurses) {
        return 0;
    }
    screenThread = std::thread(&Screen::displayLoop, this);
    return 0;
}

auto Screen::StopDisplay() -> void
{
    if (displayConf->noCurses) {
        return;
    }
    screenThread.join();
    endwin();
}

Screen::~Screen()
{
    delwin(keyWin);
    delwin(valueWin);
    delwin(keyHeaderWin);
    delwin(sortSelectionWin);
    delwin(valueHeaderWin);
    delwin(statusWin);
    delwin(menuWin);
}

} // namespace flowstats
