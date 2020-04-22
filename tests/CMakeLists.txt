find_package(Catch2 REQUIRED)

link_directories ( tests ${TINS_LIBRARY_DIRS} ${NCURSES_LIBRARY_DIRS} )

file(GLOB TESTS_SRCS *.cpp)
add_executable(tests ${TESTS_SRCS})

target_link_libraries(tests Catch2::Catch2 flowlib)
add_definitions(-DTEST_PATH="${CMAKE_CURRENT_SOURCE_DIR}")

include(CTest)
include(Catch)
catch_discover_tests(tests)
