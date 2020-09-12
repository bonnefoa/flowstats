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
        std::vector<Collector*> collectors);
    virtual ~Screen();

    auto StartDisplay() -> int;
    auto StopDisplay() -> void;
    auto getCurrentChoice() -> std::string;
    auto updateDisplay(timeval tv, bool updateOutput,
        std::optional<CaptureStat> const& captureStatus) -> void;

    [[nodiscard]] auto getDisplayConf() const { return displayConf; };

private:
    auto displayLoop() -> void;
    auto refreshPads() -> void;
    auto getActiveCollector() -> Collector*;

    auto refreshableAction(int c) -> bool;
    auto updateHeaders() -> void;
    auto updateBody() -> void;
    auto updateStatus(std::optional<CaptureStat> const& captureStat) -> void;
    auto updateMenu() -> void;
    auto updateSortSelection() -> void;
    auto updateResizeWin() -> void;

    auto isEsc(char c) -> bool;

    WINDOW* headerWin = nullptr;
    WINDOW* bodyWin = nullptr;

    WINDOW* statusWin = nullptr;
    WINDOW* bottomWin = nullptr;

    WINDOW* leftWin = nullptr;

    int maxElements = 0;
    int numberElements = 0;
    int selectedLine = 0;
    int verticalScroll = 0;

    std::thread screenThread;
    std::atomic_bool* shouldStop;
    bool shouldFreeze = false;
    timeval lastTv = {};
    timeval firstTv = {};
    DisplayConfiguration* displayConf;
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
        SORT
    } editMode = NONE;
    bool reversedSort = false;

    std::mutex screenMutex;
};
} // namespace flowstats
