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
#define DEFAULT_COLUMNS 200
#define SORT_TEXT_COLUMNS 19
#define SORT_COLUMNS 20

#define STATUS_LINES 5
#define HEADER_LINES 1
#define BODY_LINES 300
#define BOTTOM_LINES 1

#define SORT_LINES 300

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
    updateBody();

    refreshPads();
}

auto Screen::updateBody() -> void
{
    werase(bodyWin);

    auto& values = collectorOutput.getValues();
    auto numKeys = values.size();
    numberElements = int(numKeys / 2);
    for (int i = 0; i < numKeys; ++i) {
        int line = i / 2;
        if (line == selectedLine) {
            wattron(bodyWin, COLOR_PAIR(SELECTED_LINE_COLOR));
        }
        mvwprintw(bodyWin, i, 0,
            fmt::format("{:<" STR(DEFAULT_COLUMNS) "}",
                values[i].c_str())
                .c_str());
        if (line == selectedLine) {
            wattroff(bodyWin, COLOR_PAIR(SELECTED_LINE_COLOR));
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
    waddstr(statusWin, fmt::format("Running time: {}s, Filter: \"{}\"\n", lastTv.tv_sec - firstTv.tv_sec, displayConf->filter).c_str());

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
    werase(headerWin);

    wattron(headerWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(headerWin, fmt::format("{:<" STR(DEFAULT_COLUMNS) "}", collectorOutput.getHeaders()).c_str());
    wattroff(headerWin, COLOR_PAIR(KEY_HEADER_COLOR));
}

auto Screen::updateMenu() -> void
{
    werase(bottomWin);

    if (editMode == FILTER || editMode == SORT) {
        waddstr(bottomWin, "Enter: ");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<6}", "Done").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, "Esc: ");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<6}", "Clear").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, " ");
    } else {
        waddstr(bottomWin, "F4 ");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Filter").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, "r ");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Resize").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));
    }

    if (editMode == FILTER) {
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("Filter: {}", displayConf->filter).c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));
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

    define_key("\033OP", KEY_F(1));
    define_key("\033OQ", KEY_F(2));
    define_key("\033OR", KEY_F(3));
    define_key("\033OS", KEY_F(4));
    define_key("\033[11~", KEY_F(1));
    define_key("\033[12~", KEY_F(2));
    define_key("\033[13~", KEY_F(3));
    define_key("\033[14~", KEY_F(4));

    headerWin = newpad(HEADER_LINES + STATUS_LINES, DEFAULT_COLUMNS);
    bodyWin = newpad(BODY_LINES, DEFAULT_COLUMNS);

    statusWin = newwin(STATUS_LINES, DEFAULT_COLUMNS, 0, 0);
    sortSelectionWin = newwin(SORT_LINES, SORT_COLUMNS,
        STATUS_LINES, 0);
    bottomWin = newwin(BOTTOM_LINES, DEFAULT_COLUMNS, LINES - 1, 0);

    activeCollector = getActiveCollector();
}

auto Screen::isEsc(char c) -> bool
{
    if (c != KEY_ESC) {
        return false;
    }
    nodelay(stdscr, true);
    int tempC = getch();
    nodelay(stdscr, false);
    if (tempC == -1) {
        return true;
    }
    return false;
}

auto Screen::refreshPads() -> void
{
    if (displayConf->noDisplay) {
        return;
    }
    wnoutrefresh(statusWin);

    int deltaValues = 0;
    if (editMode == SORT) {
        deltaValues = SORT_COLUMNS;
        wnoutrefresh(sortSelectionWin);
    }

    int displayedColumn = std::min(DEFAULT_COLUMNS - deltaValues, COLS - 1);
    pnoutrefresh(headerWin,
        0, 0,
        STATUS_LINES, deltaValues,
        STATUS_LINES + HEADER_LINES, displayedColumn);

    pnoutrefresh(bodyWin,
        verticalScroll, 0,
        STATUS_LINES + HEADER_LINES, deltaValues,
        LINES - (HEADER_LINES + BOTTOM_LINES), displayedColumn);

    wnoutrefresh(bottomWin);
    doupdate();
}

auto Screen::refreshableAction(int c) -> bool
{
    if (editMode == FILTER) {
        if (isEsc(c)) {
            displayConf->filter = "";
            editMode = NONE;
        } else if (c == CTRL('u')) {
            displayConf->filter = "";
        } else if (c == KEY_VALID) {
            editMode = NONE;
        } else if (c == KEY_BACKSPACE && displayConf->filter.size() > 0) {
            displayConf->filter.pop_back();
        } else if (isprint(c)) {
            displayConf->filter.push_back(c);
        } else {
            return false;
        }
        return true;
    }

    if (editMode == SORT) {
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
        } else if (c == KEY_VALID || isEsc(c)) {
            editMode = NONE;
            return true;
        }
    }

    if (c >= KEY_NUM(1) && c <= KEY_NUM(3)) {
        displayConf->protocolIndex = c - KEY_NUM(1);
        activeCollector = getActiveCollector();
        return true;
    } else if (c == KEY_F(4)) {
        editMode = FILTER;
        return true;
    } else if (c == KEY_R) {
        editMode = RESIZE;
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
        editMode = SORT;
        reversedSort = false;
        activeCollector->updateSort(protocolToSortIndex[displayConf->protocolIndex], reversedSort);
        return true;
    } else if (c == KEY_INF) {
        editMode = SORT;
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

        maxElements = (LINES - (STATUS_LINES + HEADER_LINES + BOTTOM_LINES)) / 2 - 1;
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
    delwin(headerWin);
    delwin(bodyWin);
    delwin(sortSelectionWin);
    delwin(statusWin);
    delwin(bottomWin);
}

} // namespace flowstats
