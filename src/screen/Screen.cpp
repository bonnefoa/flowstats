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
#define KEY_D 100
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
#define LEFT_WIN_COLUMNS 28
#define LEFT_WIN_KEY 14

#define STATUS_LINES 3
#define TOP_MENU_LINES 2
#define HEADER_LINES 1
#define BODY_LINES 30000
#define BOTTOM_LINES 1

#define SORT_LINES 300

namespace flowstats {

std::array<CollectorProtocol, 3> protocols = { CollectorProtocol::DNS, CollectorProtocol::TCP, CollectorProtocol::SSL };

auto Screen::updateDisplay(timeval tv, bool updateOutput,
    std::optional<CaptureStat> const& captureStat) -> void
{
    if (noCurses) {
        return;
    }
    if (firstTv.tv_sec == 0) {
        firstTv = tv;
    }
    const std::lock_guard<std::mutex> lock(screenMutex);

    lastTv = tv;
    updateTopLeftStatus(captureStat);
    updateTopRightStatus();
    updateTopMenu();

    if (editMode == SORT) {
        updateSortSelection();
    } else if (editMode == RESIZE) {
        updateResizeWin();
    } else if (editMode == RATE_MODE) {
        updateRateMode();
    }
    updateBottomMenu();

    if (!shouldFreeze && updateOutput) {
        collectorOutput = activeCollector->outputStatus(tv.tv_sec - firstTv.tv_sec);
    }

    updateHeaders();
    updateBody();

    refreshPads();
}

auto Screen::updateBody() -> void
{
    werase(bodyWin);

    auto const& lineGroups = collectorOutput.getValues();
    bool strip = false;
    int screenLine = 0;
    numberElements = lineGroups.size();
    availableLines = (LINES - (STATUS_LINES + TOP_MENU_LINES + HEADER_LINES + BOTTOM_LINES));
    endLine = lineGroups.size();
    displayedElements = endLine - startLine;
    for (int lineGroupIndex = startLine; lineGroupIndex < lineGroups.size(); ++lineGroupIndex) {
        if (lineGroupIndex == selectedLine) {
            wattron(bodyWin, COLOR_PAIR(SELECTED_LINE_COLOR));
        } else if (strip) {
            wattron(bodyWin, COLOR_PAIR(UNSELECTED_LINE_STRIP_COLOR));
        }
        for (auto& line : lineGroups[lineGroupIndex]) {
            mvwprintw(bodyWin, screenLine++, 0, fmt::format("{:<" STR(DEFAULT_COLUMNS) "}", line).c_str());
        }
        if (lineGroupIndex == selectedLine) {
            wattroff(bodyWin, COLOR_PAIR(SELECTED_LINE_COLOR));
        } else if (strip) {
            wattroff(bodyWin, COLOR_PAIR(UNSELECTED_LINE_STRIP_COLOR));
        }
        strip = !strip;

        if (screenLine >= availableLines) {
            endLine = lineGroupIndex;
            displayedElements = endLine - startLine;
            return;
        }
    }
}

auto Screen::updateResizeWin() -> void
{
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
        waddstr(leftWin, fmt::format("{:<{}} {:>{}}", fieldToHeader(field), LEFT_WIN_KEY, fieldToSize[field], LEFT_WIN_COLUMNS - (LEFT_WIN_KEY + 2)).c_str());
        if (i == selectedResizeField) {
            wattroff(leftWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        i++;
        waddstr(leftWin, "\n");
    }
}

auto Screen::updateSortSelection() -> void
{
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

auto Screen::updateRateMode() -> void
{
    werase(leftWin);
    wattron(leftWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(leftWin, fmt::format("{:<{}}", "Rate Mode", LEFT_WIN_COLUMNS - 1).c_str());
    wattroff(leftWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(leftWin, " ");

    for (auto rateMode : RateMode::_values()) {
        auto currentRateMode = displayConf->getRateMode();
        if (rateMode == currentRateMode) {
            wattron(leftWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        waddstr(leftWin, fmt::format("{:<{}}", rateMode._to_string(), LEFT_WIN_COLUMNS - 1).c_str());
        if (rateMode == currentRateMode) {
            wattroff(leftWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        waddstr(leftWin, "\n");
    }
}

auto Screen::updateTopMenu() -> void
{
    werase(topMenuWin);
    waddstr(topMenuWin, fmt::format("{:<{}} ", "Protocol:", headerToSize(Header::PROTOCOL_KEY)).c_str());
    for (int i = 0; i < ARRAY_SIZE(protocols); ++i) {
        auto proto = protocols[i];
        if (selectedProtocolIndex == i) {
            wattron(topMenuWin, COLOR_PAIR(SELECTED_STATUS_COLOR));
        }
        waddstr(topMenuWin, fmt::format("{}: {:<{}}", i + 1, proto._to_string(), headerToSize(Header::PROTOCOL_VALUE) - 3).c_str());
        if (selectedProtocolIndex == i) {
            wattroff(topMenuWin, COLOR_PAIR(SELECTED_STATUS_COLOR));
        }
    }
    waddstr(topMenuWin, "\n");

    waddstr(topMenuWin, fmt::format("{:<{}} ", "Display:", headerToSize(Header::DISPLAY_KEY)).c_str());
    int i = 0;
    int displayIndex;
    displayIndex = protocolToDisplayIndex[selectedProtocolIndex];
    for (const auto& displayFieldValues : activeCollector->getDisplayFieldValues()) {
        if (i == displayIndex) {
            wattron(topMenuWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        waddstr(topMenuWin, fmt::format("{:<{}}", displayFieldValues.getDisplayTypeStr(), headerToSize(Header::DISPLAY_VALUE)).c_str());
        if (i == displayIndex) {
            wattroff(topMenuWin, COLOR_PAIR(SELECTED_VALUE_COLOR));
        }
        i++;
    }
    waddstr(topMenuWin, "\n");
}

auto Screen::updateTopLeftStatus(std::optional<CaptureStat> const& captureStat) -> void
{
    werase(statusLeftWin);
    auto const* freezeStr = "";
    if (shouldFreeze) {
        freezeStr = ", Update frozen";
    }
    waddstr(statusLeftWin, fmt::format("Running time: {}s, selectedLine {}, startLine {}, endLine {}, availableLines {}{}\n", lastTv.tv_sec - firstTv.tv_sec, selectedLine, startLine, endLine, availableLines, freezeStr).c_str());

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

    waddstr(statusLeftWin, currentCaptureStat.getTotal().c_str());
    waddstr(statusLeftWin, currentCaptureStat.getRate(previousCaptureStat).c_str());
}

auto Screen::updateTopRightStatus() -> void
{
    werase(statusRightWin);
    waddstr(statusRightWin, fmt::format("RateMode: {}\n", rateModeToDescription(displayConf->getRateMode())).c_str());
    waddstr(statusRightWin, fmt::format("Filter: \"{}\"\n", displayConf->getFilter()).c_str());
}

auto Screen::updateHeaders() -> void
{
    werase(headerWin);

    wattron(headerWin, COLOR_PAIR(KEY_HEADER_COLOR));
    waddstr(headerWin, fmt::format("{:<" STR(DEFAULT_COLUMNS) "}", collectorOutput.getHeaders()).c_str());
    wattroff(headerWin, COLOR_PAIR(KEY_HEADER_COLOR));
}

auto Screen::updateBottomMenu() -> void
{
    werase(bottomWin);

    if (editMode == FILTER || editMode == SORT || editMode == RESIZE || editMode == RATE_MODE) {
        waddstr(bottomWin, "Enter");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Done").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, "Esc");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Clear").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));
    } else {
        waddstr(bottomWin, "F4");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Filter").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, "r");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Resize").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, "f");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Freeze").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, "m");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<10}", "Merge C/S").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, "d");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<10}", "Rate Mode").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, ">");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Sort asc").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, "<");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Sort desc").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));
    }

    if (editMode == FILTER) {
        waddstr(bottomWin, " ");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("Filter: {}", displayConf->getFilter()).c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));
    }

    if (editMode == RESIZE) {
        waddstr(bottomWin, "+");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Increase").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));

        waddstr(bottomWin, "-");
        wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
        waddstr(bottomWin, fmt::format("{:<8}", "Decrease").c_str());
        wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));
    }

    wattron(bottomWin, COLOR_PAIR(MENU_COLOR));
    waddstr(bottomWin, std::string(DEFAULT_COLUMNS, ' ').c_str());
    wattroff(bottomWin, COLOR_PAIR(MENU_COLOR));
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
    setlocale(LC_ALL, "");
    initscr();

    use_default_colors();
    start_color();

    init_pair(SELECTED_STATUS_COLOR, COLOR_BLACK, COLOR_WHITE);
    init_pair(SELECTED_LINE_COLOR, COLOR_BLACK, COLOR_CYAN);
    init_pair(UNSELECTED_LINE_STRIP_COLOR, COLOR_WHITE, -1);

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

    headerWin = newpad(HEADER_LINES + STATUS_LINES + TOP_MENU_LINES, COLS);
    bodyWin = newpad(BODY_LINES, DEFAULT_COLUMNS);

    statusLeftWin = newwin(STATUS_LINES, COLS / 2, 0, 0);
    statusRightWin = newwin(STATUS_LINES, COLS / 2, 0, COLS / 2);
    topMenuWin = newwin(TOP_MENU_LINES, COLS, STATUS_LINES, 0);
    leftWin = newwin(SORT_LINES, LEFT_WIN_COLUMNS, STATUS_LINES + TOP_MENU_LINES, 0);
    bottomWin = newwin(BOTTOM_LINES, DEFAULT_COLUMNS, LINES - 1, 0);

    activeCollector = getActiveCollector();
}

auto Screen::isEsc(int c) -> bool
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

    int deltaValues = 0;
    if (editMode == SORT || editMode == RESIZE || editMode == RATE_MODE) {
        deltaValues = LEFT_WIN_COLUMNS;
        wnoutrefresh(leftWin);
    }

    int displayedColumn = std::min(DEFAULT_COLUMNS - deltaValues, COLS - 1);
    pnoutrefresh(headerWin,
        0, 0,
        STATUS_LINES + TOP_MENU_LINES, deltaValues,
        STATUS_LINES + TOP_MENU_LINES + HEADER_LINES, displayedColumn);

    pnoutrefresh(bodyWin,
        0, 0,
        STATUS_LINES + TOP_MENU_LINES + HEADER_LINES, deltaValues,
        LINES - (HEADER_LINES + BOTTOM_LINES), displayedColumn);

    wnoutrefresh(statusLeftWin);
    wnoutrefresh(statusRightWin);
    wnoutrefresh(topMenuWin);
    wnoutrefresh(bottomWin);
    doupdate();
}

auto Screen::refreshableAction(int c) -> bool
{
    const std::lock_guard<std::mutex> lock(screenMutex);
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

    if (editMode == RATE_MODE) {
        if (c == KEY_DOWN) {
            displayConf->nextRateMode();
            return true;
        } else if (c == KEY_UP) {
            displayConf->previousRateMode();
            return true;
        }
    }

    if (editMode == RESIZE) {
        auto* flowFormatter = activeCollector->getFlowFormatterPtr();
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
        auto maxSort = static_cast<int>(activeCollector->getSortFields().size());
        if (c == KEY_UP) {
            protocolToSortIndex[selectedProtocolIndex] = getWithWarparound(protocolToSortIndex[selectedProtocolIndex], maxSort, -1);
            activeCollector->updateSort(protocolToSortIndex[selectedProtocolIndex], reversedSort);
            return true;
        } else if (c == KEY_DOWN) {
            protocolToSortIndex[selectedProtocolIndex] = getWithWarparound(protocolToSortIndex[selectedProtocolIndex], maxSort, 1);
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
    } else if (c == KEY_D) {
        editMode = RATE_MODE;
        return true;
    } else if (c == KEY_M) {
        displayConf->toggleMergedDirection();
        return true;
    } else if (c == KEY_LEFT) {
        protocolToDisplayIndex[selectedProtocolIndex] = getWithWarparound(protocolToDisplayIndex[selectedProtocolIndex],
            static_cast<int>(activeCollector->getDisplayFieldValues().size()), -1);
        activeCollector->updateDisplayType(protocolToDisplayIndex[selectedProtocolIndex]);
        return true;
    } else if (c == KEY_RIGHT) {
        protocolToDisplayIndex[selectedProtocolIndex] = getWithWarparound(protocolToDisplayIndex[selectedProtocolIndex],
            static_cast<int>(activeCollector->getDisplayFieldValues().size()), 1);
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

        {
            if (refreshableAction(c)) {
                updateDisplay(lastTv, true, {});
                continue;
            }

            const std::lock_guard<std::mutex> lock(screenMutex);
            switch (c) {
                case KEY_LETTER_F:
                    shouldFreeze = !shouldFreeze;
                    break;
                case KEY_UP:
                    selectedLine = std::max(selectedLine - 1, 0);
                    if (selectedLine < startLine) {
                        startLine = selectedLine;
                    }
                    break;
                case KEY_DOWN:
                    selectedLine = std::min(selectedLine + 1, numberElements - 1);
                    if (selectedLine > endLine) {
                        startLine++;
                    }
                    break;
                case KEY_PPAGE:
                    selectedLine = std::max(selectedLine - 20, 0);
                    if (selectedLine < startLine) {
                        startLine = selectedLine;
                    }
                    break;
                case KEY_NPAGE:
                    selectedLine = std::min(selectedLine + 20, numberElements - 1);
                    if (selectedLine > endLine) {
                        startLine = selectedLine - displayedElements;
                    }
                    break;
            }
        }
        updateDisplay(lastTv, false, {});
    }
}

auto Screen::startDisplay() -> int
{
    if (noCurses) {
        return 0;
    }
    screenThread = std::thread(&Screen::displayLoop, this);
    return 0;
}

auto Screen::stopDisplay() -> void
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
    delwin(statusLeftWin);
    delwin(statusRightWin);
    delwin(topMenuWin);
    delwin(bottomWin);
}

} // namespace flowstats
