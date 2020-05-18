#pragma once

#include "Collector.hpp"
#include "CollectorOutput.hpp"
#include "Configuration.hpp"
#include <atomic>
#include <iostream>
#include <menu.h>
#include <mutex>
#include <ncurses.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace flowstats {

class Screen {
public:
    Screen(std::atomic_bool* shouldStop,
        DisplayConfiguration& displayConf,
        std::vector<Collector*> collectors);
    Screen(Screen const& s)
        : keyWin(s.keyWin)
        , valueWin(s.valueWin)
        , keyHeaderWin(s.keyHeaderWin)
        , valueHeaderWin(s.valueHeaderWin)
        , statusWin(s.statusWin)
        , menuWin(s.menuWin)
        , shouldStop(s.shouldStop)
        , displayConf(s.displayConf)
        , activeCollector(s.activeCollector) {};
    virtual ~Screen();

    auto StartDisplay() -> int;
    auto StopDisplay() -> void;
    auto getCurrentChoice() -> std::string;
    auto updateDisplay(int ts, bool updateOutput) -> void;

private:
    auto displayLoop() -> void;
    auto refreshPads() -> void;
    auto getActiveCollector() -> Collector*;

    auto refreshableAction(int c) -> bool;
    auto updateHeaders() -> void;
    auto updateValues() -> void;
    auto updateStatus() -> void;
    auto updateMenu() -> void;
    auto updateSortSelection() -> void;

    WINDOW* keyWin;
    WINDOW* valueWin;

    WINDOW* keyHeaderWin;
    WINDOW* valueHeaderWin;

    WINDOW* statusWin;
    WINDOW* menuWin;

    WINDOW* sortSelectionWin;

    int maxElements = 0;
    int numberElements = 0;
    int selectedLine = 0;
    int verticalScroll = 0;

    std::thread screenThread;
    std::atomic_bool* shouldStop;
    bool shouldFreeze = false;
    int lastTs = 0;
    int firstTs = 0;
    DisplayConfiguration& displayConf;
    std::vector<Collector*> collectors;
    Collector* activeCollector;
    CollectorOutput collectorOutput;

    bool editFilter = false;
    bool editSort = false;
    bool reversedSort = false;

    std::mutex screenMutex;
};
} // namespace flowstats
