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
    Screen(std::atomic_bool* shouldStop, bool noCurses,
        FlowstatsConfiguration& conf, DisplayConfiguration& displayConf,
        std::vector<Collector*> collectors);
    virtual ~Screen();

    auto StartDisplay() -> int;
    auto StopDisplay() -> void;
    auto getCurrentChoice() -> std::string;
    auto updateDisplay(int duration, bool updateOutput) -> void;

private:
    auto displayLoop() -> void;
    auto refreshPads() -> void;
    auto getActiveCollector() -> Collector*;

    auto refreshableAction(int c) -> bool;
    auto updateHeaders() -> void;
    auto updateValues() -> void;
    auto updateStatus(int duration) -> void;
    auto updateMenu() -> void;

    WINDOW* keyWin;
    WINDOW* valueWin;

    WINDOW* keyHeaderWin;
    WINDOW* valueHeaderWin;

    WINDOW* statusWin;
    WINDOW* menuWin;

    int maxElements = 0;
    int numberElements = 0;
    int selectedLine = 0;
    int verticalScroll = 0;

    std::thread screenThread;
    std::atomic_bool* shouldStop;
    bool shouldFreeze = false;
    bool noCurses;
    int lastDuration {};
    FlowstatsConfiguration& conf;
    DisplayConfiguration& displayConf;
    std::vector<Collector*> collectors;
    Collector* activeCollector;
    CollectorOutput collectorOutput;

    bool editFilter = false;

    std::mutex screenMutex;
};
} // namespace flowstats
