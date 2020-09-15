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
#define KEY_M 109
#define KEY_P 112
#define KEY_Q 113
#define KEY_R 114
#define KEY_S 115
#define KEY_VALID '\n'
#define KEY_PLUS 43
#define KEY_MINUS 45

#define KEY_0 48
#define KEY_NUM(n) (KEY_0 + (n))

// Sizes
#define DEFAULT_COLUMNS 200
#define LEFT_WIN_COLUMNS 20

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
int selectedResizeField = 0;

auto Screen::updateDisplay(timeval tv, bool updateOutput,
    std::optional<CaptureStat> const& captureStat) -> void
{
    if (noCurses) {
        return;
    }
    if (firstTv.tv_sec == 0) {
        firstTv = tv;
    }
    lastTv = tv;

    const std::lock_guard<std::mutex> lock(screenMutex);
    updateStatus(captureStat);
    updateSortSelection();
    updateResizeWin();
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
    int coefficient = displayConf->getMergeDirection() ? 1 : 2;
    numberElements = int(numKeys / coefficient);
    for (int i = 0; i < numKeys; ++i) {
        int line = i / coefficient;
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

auto Screen::updateResizeWin() -> void
{
    if (editMode != RESIZE) {
        return;
    }
    werase(leftWin);
    wattron(leftWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(leftWin, fmt::format("{:<{}}", "Field Size", LEFT_WIN_COLUMNS - 1).c_str());
    wattroff(leftWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(leftWin, " ");

    auto flowFormatter = activeCollector->getFlowFormatter();
    auto displayFields = flowFormatter.getDisplayFields();
    auto fieldToSize = displayConf->getFieldToSize();
    int i = 0;
    for (auto field : displayFields) {
        if (i == selectedResizeField) {
            wattron(leftWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        waddstr(leftWin, fmt::format("{:<10} {:>{}}", fieldToHeader(field), fieldToSize[field], LEFT_WIN_COLUMNS - 12).c_str());
        if (i == selectedResizeField) {
            wattroff(leftWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        i++;
        waddstr(leftWin, "\n");
    }


}

auto Screen::updateSortSelection() -> void
{
    if (editMode != SORT) {
        return;
    }
    werase(leftWin);
    wattron(leftWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(leftWin, fmt::format("{:<{}}", "Sort by", LEFT_WIN_COLUMNS - 1).c_str());
    wattroff(leftWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(leftWin, " ");

    int i = 0;
    int displayIndex = protocolToSortIndex[selectedProtocolIndex];
    for (const auto& sortField : activeCollector->getSortFields()) {
        if (i == displayIndex) {
            wattron(leftWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        waddstr(leftWin, fmt::format("{:<{}}", fieldToHeader(sortField), LEFT_WIN_COLUMNS - 1).c_str());
        if (i == displayIndex) {
            wattroff(leftWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        i++;
        waddstr(leftWin, "\n");
    }
}

auto Screen::updateStatus(std::optional<CaptureStat> const& captureStat) -> void
{
    werase(statusWin);
    waddstr(statusWin, fmt::format("Running time: {}s, Filter: \"{}\"\n", lastTv.tv_sec - firstTv.tv_sec, displayConf->getFilter()).c_str());

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
        if (selectedProtocolIndex == i) {
            wattron(statusWin, COLOR_PAIR(SELECTED_STATUS_COLOR));
        }
        waddstr(statusWin, fmt::format("{}: {:<10} ", i + 1, proto._to_string()).c_str());
        if (selectedProtocolIndex == i) {
            wattroff(statusWin, COLOR_PAIR(SELECTED_STATUS_COLOR));
        }
    }
    waddstr(statusWin, "\n");

    waddstr(statusWin, fmt::format("{:<10} ", "Display:").c_str());
    int i = 0;
    int displayIndex = protocolToDisplayIndex[selectedProtocolIndex];
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

    if (editMode == FILTER || editMode == SORT || editMode == RESIZE) {
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

        waddstr(bottomWin, "R ");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Resize").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, "M ");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<10}", "Merge C/S").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));
    }

    if (editMode == FILTER) {
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("Filter: {}", displayConf->getFilter()).c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));
    }
}

auto Screen::getActiveCollector() -> Collector*
{
    for (auto& collector : collectors) {
        if (protocols[selectedProtocolIndex] != collector->getProtocol()) {
            continue;
        }
        return collector;
    }
    return nullptr;
}

Screen::Screen(std::atomic_bool* shouldStop,
    DisplayConfiguration* displayConf,
    bool noCurses, bool noDisplay, bool pcapReplay,
    std::vector<Collector*> collectors)
    : shouldStop(shouldStop)
    , displayConf(displayConf)
    , noCurses(noCurses)
    , noDisplay(noDisplay)
    , pcapReplay(pcapReplay)
    , collectors(std::move(std::move(collectors)))
{
    if (noCurses) {
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
    leftWin = newwin(SORT_LINES, LEFT_WIN_COLUMNS, STATUS_LINES, 0);
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
    if (noDisplay) {
        return;
    }
    wnoutrefresh(statusWin);

    int deltaValues = 0;
    if (editMode == SORT || editMode == RESIZE) {
        deltaValues = LEFT_WIN_COLUMNS;
        wnoutrefresh(leftWin);
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
    if (c == KEY_VALID) {
        editMode = NONE;
        return true;
    }

    if (editMode == FILTER) {
        if (isEsc(c)) {
            displayConf->emptyFilter();
            editMode = NONE;
        } else if (c == CTRL('u')) {
            displayConf->emptyFilter();
        } else if (c == KEY_BACKSPACE && displayConf->getFilter().size() > 0) {
            displayConf->removeFilterChar();
        } else if (isprint(c)) {
            displayConf->addFilterChar(c);
        } else {
            return false;
        }
        return true;
    }

    if (editMode == RESIZE) {
        auto flowFormatter = activeCollector->getFlowFormatterPtr();
        if (c == KEY_DOWN) {
            int numFields = flowFormatter->getDisplayFields().size();
            selectedResizeField = std::min(selectedResizeField + 1, numFields - 1);
            return true;
        } else if (c == KEY_UP) {
            selectedResizeField = std::max(selectedResizeField - 1, 0);
            return true;
        } else if (c == KEY_PLUS) {
            auto field = flowFormatter->getDisplayFields()[selectedResizeField];
            displayConf->updateFieldSize(field, 2);
            return true;
        } else if (c == KEY_MINUS) {
            auto field = flowFormatter->getDisplayFields()[selectedResizeField];
            displayConf->updateFieldSize(field, -2);
            return true;
        } else if (isEsc(c)) {
            editMode = NONE;
        }
        return false;
    }

    if (editMode == SORT) {
        if (c == KEY_UP) {
            protocolToSortIndex[selectedProtocolIndex] = std::max(
                protocolToSortIndex[selectedProtocolIndex] - 1, 0);
            activeCollector->updateSort(protocolToSortIndex[selectedProtocolIndex], reversedSort);
            return true;
        } else if (c == KEY_DOWN) {
            protocolToSortIndex[selectedProtocolIndex] = std::min(
                protocolToSortIndex[selectedProtocolIndex] + 1,
                static_cast<int>(activeCollector->getSortFields().size()) - 1);
            activeCollector->updateSort(protocolToSortIndex[selectedProtocolIndex], reversedSort);
            return true;
        } else if (isEsc(c)) {
            editMode = NONE;
            return true;
        }
    }

    if (c >= KEY_NUM(1) && c <= KEY_NUM(3)) {
        selectedProtocolIndex = c - KEY_NUM(1);
        activeCollector = getActiveCollector();
        return true;
    } else if (c == KEY_F(4)) {
        editMode = FILTER;
        return true;
    } else if (c == KEY_R) {
        editMode = RESIZE;
        return true;
    } else if (c == KEY_M) {
        displayConf->toggleMergedDirection();
        return true;
    } else if (c == KEY_LEFT) {
        protocolToDisplayIndex[selectedProtocolIndex] = std::max(
            protocolToDisplayIndex[selectedProtocolIndex] - 1, 0);
        activeCollector->updateDisplayType(protocolToDisplayIndex[selectedProtocolIndex]);
        return true;
    } else if (c == KEY_RIGHT) {
        protocolToDisplayIndex[selectedProtocolIndex] = std::min(
            protocolToDisplayIndex[selectedProtocolIndex] + 1,
            static_cast<int>(activeCollector->getDisplayPairs().size()) - 1);
        activeCollector->updateDisplayType(protocolToDisplayIndex[selectedProtocolIndex]);
        return true;
    } else if (c == KEY_SUP) {
        editMode = SORT;
        reversedSort = false;
        activeCollector->updateSort(protocolToSortIndex[selectedProtocolIndex], reversedSort);
        return true;
    } else if (c == KEY_INF) {
        editMode = SORT;
        reversedSort = true;
        activeCollector->updateSort(protocolToSortIndex[selectedProtocolIndex], reversedSort);
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
            if (pcapReplay) {
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

        int coefficient = displayConf->getMergeDirection() ? 1 : 2;
        maxElements = (LINES - (STATUS_LINES + HEADER_LINES + BOTTOM_LINES)) / coefficient - 1;
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
        if (selectedLine * coefficient < verticalScroll) {
            verticalScroll = selectedLine * coefficient;
        } else if (selectedLine * coefficient > (maxElements * coefficient + verticalScroll)) {
            verticalScroll += selectedLine * coefficient - (maxElements * coefficient + verticalScroll);
        }
        updateDisplay(lastTv, false, {});
    }
}

auto Screen::StartDisplay() -> int
{
    if (noCurses) {
        return 0;
    }
    screenThread = std::thread(&Screen::displayLoop, this);
    return 0;
}

auto Screen::StopDisplay() -> void
{
    if (noCurses) {
        return;
    }
    screenThread.join();
    endwin();
}

Screen::~Screen()
{
    delwin(headerWin);
    delwin(bodyWin);
    delwin(leftWin);
    delwin(statusWin);
    delwin(bottomWin);
}

} // namespace flowstats
