cmake_minimum_required(VERSION 3.1)

project (flowstats)

SET( CMAKE_EXPORT_COMPILE_COMMANDS ON )
SET( CMAKE_CXX_STANDARD 17 )
SET( CMAKE_CXX_COMPILER clang++)
set (CMAKE_CXX_FLAGS_DEBUG "-g -O0 -fPIE -fno-omit-frame-pointer")

find_package (PkgConfig)
find_package(Threads REQUIRED)
pkg_check_modules (PCAPPLUSPLUS REQUIRED PcapPlusPlus)
pkg_check_modules (NCURSES REQUIRED ncurses)
pkg_check_modules (FMT REQUIRED fmt)
pkg_check_modules (SPDLOG REQUIRED spdlog )
pkg_check_modules (TCMALLOC REQUIRED libtcmalloc)

option(BUILD_STATICS_EXEC "Build statics executable" OFF)
option(BUILD_TSAN "Build with tsan" OFF)
option(BUILD_ASAN "Build with asan" OFF)
option(BUILD_PROFILER "Build with profiler" OFF)
option(ENABLE_TESTS "Enable tests" OFF)

set(ADDITIONAL_LIBRARIES "")
set(ADDITIONAL_EXECUTABLE_LIBRARIES "")
if(BUILD_STATICS_EXEC)
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBS OFF)
    SET(CMAKE_EXE_LINKER_FLAGS "-static")
endif()

if(BUILD_TSAN)
    SET(CMAKE_EXE_LINKER_FLAGS "-fsanitize=thread")
endif()

if(BUILD_ASAN)
    SET(CMAKE_EXE_LINKER_FLAGS "-fsanitize=address -fno-omit-frame-pointer")
endif()

if(BUILD_PROFILER)
    pkg_check_modules (PROFILER REQUIRED libprofiler)
    pkg_check_modules (UNWIND REQUIRED libunwind)
    pkg_check_modules (LZMA REQUIRED liblzma)
    list(APPEND ADDITIONAL_EXECUTABLE_LIBRARIES "-Wl,--no-as-needed" ${PROFILER_LIBRARIES} "-Wl,--as-needed" "${UNWIND_LIBRARIES}" "${LZMA_LIBRARIES}" "-Wl,--allow-multiple-definition")
endif()

add_subdirectory( src )

if (ENABLE_TESTS)
enable_testing()
add_subdirectory( tests )
endif()
