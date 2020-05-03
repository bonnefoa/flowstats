#include "Screen.hpp"
#include "Utils.hpp"
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <tins/dns.h>
#include <tins/tcp.h>
#include <utility>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define CTRL(x) ((x)&0x1f)

#define KEY_B 98
#define KEY_LETTER_F 102
#define KEY_P 112
#define KEY_Q 113
#define KEY_R 114
#define KEY_S 115

#define KEY_0 48
#define KEY_NUM(n) (KEY_0 + (n))

// Sizes
#define STATUS_LINES 5
#define STATUS_COLUMNS 120

#define HEADER_LINES 2

#define KEY_LINES 300
#define KEY_COLUMNS 89

#define VALUE_LINES 300
#define VALUE_COLUMNS 100

#define MENU_LINES 1
#define MENU_COLUMNS 120

// Colors
#define SELECTED_STATUS_COLOR 1
#define SELECTED_LINE_COLOR 2
#define MENU_COLOR 3
#define SELECTED_VALUE_COLOR 4
#define KEY_HEADER_COLOR 5
#define VALUE_HEADER_COLOR 6

namespace flowstats {

int lastKey = 0;
std::array<CollectorProtocol, 3> protocols = { DNS, TCP, SSL };
std::array<int, 3> protocolToDisplayIndex = { 0, 0, 0 };

auto Screen::updateDisplay(int duration, bool updateOutput) -> void
{
    if (displayConf.noCurses) {
        return;
    }
    lastDuration = duration;

    const std::lock_guard<std::mutex> lock(screenMutex);
    updateStatus(duration);
    updateMenu();

    if (shouldFreeze == true) {
        refreshPads();
        return;
    }

    if (updateOutput) {
        collectorOutput = activeCollector->outputStatus(duration);
    }

    updateHeaders();
    updateValues();

    refreshPads();
}

auto Screen::updateValues() -> void
{
    werase(keyWin);
    werase(valueWin);

    numberElements = int(collectorOutput.getKeys().size() / 2);
    for (int i = 0; i < collectorOutput.getKeys().size(); ++i) {
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

auto Screen::updateStatus(int duration) -> void
{
    werase(statusWin);
    mvwprintw(statusWin, 0, 0, fmt::format("Freeze: {}, last key {}, Filter {}, line {}\n", shouldFreeze, lastKey, displayConf.filter, selectedLine).c_str());

    waddstr(statusWin, fmt::format("Running time: {}s\n", duration).c_str());

    waddstr(statusWin, fmt::format("{:<10} ", "Protocol:").c_str());
    for (int i = 0; i < ARRAY_SIZE(protocols); ++i) {
        auto proto = protocols[i];
        if (displayConf.protocolIndex == i) {
            wattron(statusWin, COLOR_PAIR(SELECTED_STATUS_COLOR));
        }
        waddstr(statusWin, fmt::format("{}: {:<10} ", i + 1, collectorProtocolToString(proto)).c_str());
        if (displayConf.protocolIndex == i) {
            wattroff(statusWin, COLOR_PAIR(SELECTED_STATUS_COLOR));
        }
    }
    waddstr(statusWin, "\n");

    waddstr(statusWin, fmt::format("{:<10} ", "Sort:").c_str());
    for (int sortType = 0; sortType <= SortSrt; ++sortType) {
        if (displayConf.sortType == sortType) {
            wattron(statusWin, COLOR_PAIR(SELECTED_STATUS_COLOR));
        }
        waddstr(statusWin,
            fmt::format("{}: {:<10} ", sortType + 4,
                sortToString((enum SortType)sortType))
                .c_str());
        if (displayConf.sortType == sortType) {
            wattroff(statusWin, COLOR_PAIR(SELECTED_STATUS_COLOR));
        }
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

    int i = 0;
    int displayIndex = protocolToDisplayIndex[displayConf.protocolIndex];
    for (const auto& displayPair : activeCollector->getDisplayPairs()) {
        if (i == displayIndex) {
            wattron(valueHeaderWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        waddstr(valueHeaderWin, fmt::format("{:<14}", displayTypeToString(displayPair.first)).c_str());
        if (i == displayIndex) {
            wattroff(valueHeaderWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        i++;
    }
    waddstr(valueHeaderWin, "\n");

    wattron(valueHeaderWin, COLOR_PAIR(VALUE_HEADER_COLOR));
    waddstr(valueHeaderWin, fmt::format("{:<" STR(VALUE_COLUMNS) "}", collectorOutput.getValueHeaders()).c_str());
    wattroff(valueHeaderWin, COLOR_PAIR(VALUE_HEADER_COLOR));
}

auto Screen::updateMenu() -> void
{
    werase(menuWin);

    if (editFilter) {
        waddstr(menuWin, "Enter: ");
        wattron(menuWin, COLOR_PAIR(MENU_COLOR));
        waddstr(menuWin, fmt::format("{:<6}", "Done").c_str());
        wattroff(menuWin, COLOR_PAIR(MENU_COLOR));

        waddstr(menuWin, "Esc: ");
        wattron(menuWin, COLOR_PAIR(MENU_COLOR));
        waddstr(menuWin, fmt::format("{:<6}", "Clear").c_str());
        wattroff(menuWin, COLOR_PAIR(MENU_COLOR));

        waddstr(menuWin, " ");

        wattron(menuWin, COLOR_PAIR(MENU_COLOR));
        waddstr(menuWin, fmt::format("Filter: {}", displayConf.filter).c_str());
        wattroff(menuWin, COLOR_PAIR(MENU_COLOR));
    } else {
        waddstr(menuWin, "F4 ");
        wattron(menuWin, COLOR_PAIR(MENU_COLOR));
        waddstr(menuWin, fmt::format("{:<6}", "Filter").c_str());
        wattroff(menuWin, COLOR_PAIR(MENU_COLOR));
    }
}

auto Screen::getActiveCollector() -> Collector*
{
    for (auto& collector : collectors) {
        if (protocols[displayConf.protocolIndex] != collector->getProtocol()) {
            continue;
        }
        return collector;
    }
    return nullptr;
}

Screen::Screen(std::atomic_bool* shouldStop,
    DisplayConfiguration& displayConf,
    std::vector<Collector*> collectors)
    : shouldStop(shouldStop)
    , displayConf(displayConf)
    , collectors(std::move(std::move(collectors)))
{
    if (displayConf.noCurses) {
        return;
    }
    initscr();

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

    keyWin = newpad(KEY_LINES, KEY_COLUMNS);
    valueWin = newpad(VALUE_LINES, VALUE_COLUMNS);
    keyHeaderWin = newpad(HEADER_LINES + STATUS_LINES, KEY_COLUMNS);
    valueHeaderWin = newpad(HEADER_LINES + STATUS_LINES, VALUE_COLUMNS);

    statusWin = newwin(STATUS_LINES, STATUS_COLUMNS, 0, 0);
    menuWin = newwin(MENU_LINES, MENU_COLUMNS, LINES - 1, 0);

    activeCollector = getActiveCollector();
}

auto Screen::refreshPads() -> void
{
    wnoutrefresh(statusWin);

    pnoutrefresh(keyHeaderWin,
        0, 0,
        STATUS_LINES + 1, 0,
        STATUS_LINES + HEADER_LINES, KEY_COLUMNS);

    pnoutrefresh(valueHeaderWin,
        0, 0,
        STATUS_LINES, KEY_COLUMNS,
        STATUS_LINES + HEADER_LINES, COLS - 1);

    pnoutrefresh(keyWin,
        verticalScroll, 0,
        STATUS_LINES + HEADER_LINES, 0,
        LINES - (HEADER_LINES + MENU_LINES), KEY_COLUMNS);

    pnoutrefresh(valueWin,
        verticalScroll, 0,
        STATUS_LINES + HEADER_LINES, KEY_COLUMNS,
        LINES - (HEADER_LINES + MENU_LINES), COLS - 1);

    wnoutrefresh(menuWin);
    doupdate();
}

auto Screen::refreshableAction(int c) -> bool
{
    if (editFilter) {
        if (c == 27) {
            nodelay(stdscr, true);
            c = getch();
            nodelay(stdscr, false);
            if (c == -1) {
                displayConf.filter = "";
                editFilter = false;
            }
        } else if (c == CTRL('u')) {
            displayConf.filter = "";
        } else if (c == '\n') {
            editFilter = false;
        } else if (c == KEY_BACKSPACE && displayConf.filter.size() > 0) {
            displayConf.filter.pop_back();
        } else if (isprint(c)) {
            displayConf.filter.push_back(c);
        } else {
            return false;
        }
        return true;
    }

    if (c >= KEY_NUM(1) && c <= KEY_NUM(9)) {
        if (c <= KEY_NUM(3)) {
            displayConf.protocolIndex = c - KEY_NUM(1);
            activeCollector = getActiveCollector();
        } else {
            displayConf.sortType = static_cast<enum SortType>(c - KEY_NUM(4));
        }
        return true;
    } else if (c == KEY_F(4)) {
        editFilter = true;
        return true;
    } else if (c == KEY_LEFT) {
        protocolToDisplayIndex[displayConf.protocolIndex] = std::max(
            protocolToDisplayIndex[displayConf.protocolIndex] - 1, 0);
        activeCollector->updateDisplayType(protocolToDisplayIndex[displayConf.protocolIndex]);
        return true;
    } else if (c == KEY_RIGHT) {
        protocolToDisplayIndex[displayConf.protocolIndex] = std::min(
            protocolToDisplayIndex[displayConf.protocolIndex] + 1,
            static_cast<int>(activeCollector->getDisplayPairs().size()) - 1);
        activeCollector->updateDisplayType(protocolToDisplayIndex[displayConf.protocolIndex]);
        return true;
    }

    return false;
}

auto Screen::displayLoop() -> void
{
    int c;
    while (shouldStop->load() == false) {

        c = getch();
        lastKey = c;
        if (c == KEY_Q || c == CTRL('c')) {
            shouldStop->store(true);
            return;
        }

        if (refreshableAction(c)) {
            updateDisplay(lastDuration, true);
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
        updateDisplay(lastDuration, false);
    }
}

auto Screen::StartDisplay() -> int
{
    if (displayConf.noCurses) {
        return 0;
    }
    screenThread = std::thread(&Screen::displayLoop, this);
    return 0;
}

auto Screen::StopDisplay() -> void
{
    if (displayConf.noCurses) {
        return;
    }
    screenThread.join();
    endwin();
}

Screen::~Screen()
    = default;
} // namespace flowstats
