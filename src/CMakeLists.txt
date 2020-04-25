if(APPLE)
    list(APPEND ADDITIONAL_LIBRARIES "-framework SystemConfiguration -framework CoreFoundation")
endif()

link_directories (${TINS_LIBRARY_DIRS} ${NCURSES_LIBRARY_DIRS})

file(GLOB UTILS_SRCS utils/*.cpp)
file(GLOB SCREEN_SRCS screen/*.cpp)
file(GLOB FLOW_SRCS flow/*.cpp)
file(GLOB COLLECTOR_SRCS collector/*.cpp)
file(GLOB PKTSOURCE_SRCS pktsource/*.cpp)

# Library
add_library(flowlib ${PKTSOURCE_SRCS} ${UTILS_SRCS} ${SCREEN_SRCS} ${PKTSOURCE_SRCS} ${FLOW_SRCS} ${COLLECTOR_SRCS})
target_link_libraries(flowlib ${SPDLOG_LDFLAGS} ${NCURSES_LIBRARIES}
    ${FMT_LIBRARIES} ${TINS_LIBRARIES} ${ADDITIONAL_LIBRARIES})
target_compile_options(flowlib PUBLIC ${TINS_CFLAGS_OTHER} ${NCURSES_CFLAGS_OTHER} ${SPDLOG_CFLAGS_OTHER} -Wall)
target_include_directories(flowlib PUBLIC ${FMT_INCLUDE_DIRS} ${SPDLOG_INCLUDE_DIRS} ${NCURSES_INCLUDE_DIRS} ${TINS_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/utils ${CMAKE_CURRENT_SOURCE_DIR}/collector ${CMAKE_CURRENT_SOURCE_DIR}/screen
    ${CMAKE_CURRENT_SOURCE_DIR}/collector ${CMAKE_CURRENT_SOURCE_DIR}/pktsource ${CMAKE_CURRENT_SOURCE_DIR}/flow)

# Executable
add_executable(flowstats flowstats.cpp)
target_link_libraries(flowstats flowlib ${ADDITIONAL_EXECUTABLE_LIBRARIES})
