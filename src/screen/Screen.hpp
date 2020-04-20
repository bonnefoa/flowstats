#pragma once

#include "Collector.hpp"
#include "CollectorOutput.hpp"
#include "Configuration.hpp"
#include <atomic>
#include <iostream>
#include <menu.h>
#include <mutex>
#include <ncurses.h>
#include <signal.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace flowstats {

class Screen {
public:
    Screen(std::atomic_bool& shouldStop, bool noCurses,
        FlowstatsConfiguration& conf, DisplayConfiguration& displayConf,
        std::vector<Collector*> collectors);
    virtual ~Screen();

    int StartDisplay();
    void StopDisplay();
    std::string getCurrentChoice();
    void updateDisplay(int duration, bool updateOutput);

private:
    void displayLoop();
    void refreshPads();
    Collector* getActiveCollector();

    bool refreshableAction(int c);
    void updateHeaders();
    void updateValues();
    void updateStatus(int duration);
    void updateMenu();

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
    std::atomic_bool& shouldStop;
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
}
