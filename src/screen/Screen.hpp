#pragma once

#include "Collector.hpp"
#include "CollectorOutput.hpp"
#include "Configuration.hpp"
#include "Stats.hpp"
#include <atomic>
#include <iostream>
#include <menu.h>
#include <mutex>
#include <ncurses.h>
#include <pcap/pcap.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace flowstats {

class Screen {
public:
    Screen(std::atomic_bool* shouldStop,
        DisplayConfiguration* displayConf,
        bool noCurses, bool noDisplay, bool pcapReplay,
        std::vector<Collector*> collectors);
    virtual ~Screen();

    auto startDisplay() -> int;
    auto stopDisplay() -> void;
    auto updateDisplay(timeval tv, bool updateOutput,
        std::optional<CaptureStat> const& captureStatus) -> void;

    [[nodiscard]] auto getCurrentChoice() -> std::string;
    [[nodiscard]] auto getNoCurses() const { return noCurses; };
    [[nodiscard]] auto getDisplayConf() const { return displayConf; };

private:
    auto displayLoop() -> void;
    auto refreshPads() -> void;
    auto getActiveCollector() -> Collector*;

    auto refreshableAction(int c) -> bool;
    auto updateHeaders() -> void;
    auto updateBody() -> void;
    auto updateTopLeftStatus(std::optional<CaptureStat> const& captureStat) -> void;
    auto updateTopMenu() -> void;
    auto updateTopRightStatus() -> void;
    auto updateBottomMenu() -> void;
    auto updateSortSelection() -> void;
    auto updateResizeWin() -> void;
    auto updateRateMode() -> void;

    auto isEsc(int c) -> bool;

    WINDOW* headerWin = nullptr;
    WINDOW* bodyWin = nullptr;

    WINDOW* statusLeftWin = nullptr;
    WINDOW* statusRightWin = nullptr;
    WINDOW* topMenuWin = nullptr;
    WINDOW* bottomWin = nullptr;

    WINDOW* leftWin = nullptr;

    int startLine = 0;
    int endLine = 0;
    int selectedLine = 0;
    int availableLines = 0;
    int displayedElements = 0;

    int numberElements = 0;

    int selectedProtocolIndex = 0;
    int selectedResizeField = 0;
    int lastKey = 0;
    std::array<int, 3> protocolToDisplayIndex = { 0, 0, 0 };
    std::array<int, 3> protocolToSortIndex = { 0, 0, 0 };

    std::atomic_bool* shouldStop;
    bool shouldFreeze = false;

    DisplayConfiguration* displayConf;
    bool noCurses = false;
    bool noDisplay = false;
    bool pcapReplay = false;

    std::thread screenThread;
    timeval lastTv = {};
    timeval firstTv = {};
    std::vector<Collector*> collectors;
    Collector* activeCollector;
    CollectorOutput collectorOutput;

    timeval lastCaptureStatUpdate = {};
    CaptureStat stagingCaptureStat;
    CaptureStat currentCaptureStat;
    CaptureStat previousCaptureStat;

    enum editMode {
        NONE,
        FILTER,
        RESIZE,
        RATE_MODE,
        SORT
    } editMode
        = NONE;

    enum lineColor {
        SELECTED_STATUS_COLOR = 1,
        MENU_COLOR,

        SELECTED_LINE_COLOR,
        UNSELECTED_LINE_STRIP_COLOR,
        SELECTED_VALUE_COLOR,

        KEY_HEADER_COLOR,
        VALUE_HEADER_COLOR,
    };

    bool reversedSort = false;

    std::mutex screenMutex;
};
} // namespace flowstats
