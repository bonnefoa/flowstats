#pragma once

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

////////////////////////////////////////////////////////////////
// DogStatsD
//
//     Configuration for communicating with the DogStatsD agent
//     Allow overriding the defaults by using `-D` compiler
//     flag.
//
//     Override the default port
//         E.G. - g++ (...) -DDOGSTATSD_HOST=12345
//
//     Override the default host
//         E.G. - g++ (...) -DDOGSTATSD_PORT="255.255.255.255"
//
#ifndef DOGSTATSD_HOST
#define DOGSTATSD_HOST "127.0.0.1"
#endif
#ifndef DOGSTATSD_PORT
#define DOGSTATSD_PORT 8125
#endif

////////////////////////////////////////////////////////////////
// UDP Send
//
#if defined(__linux__) || defined(__APPLE__)
//
//     Linux and Apple (POSIX-ish)
//
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#define UDP_SEND_DATAGRAM(data, length, path, port)          \
    do {                                                     \
        struct sockaddr_in client;                           \
        int fd = socket(AF_INET, SOCK_DGRAM, 0);             \
        if (fd == -1)                                        \
            return false;                                    \
        int size = static_cast<int>(sizeof(client));         \
        std::memset(&client, 0, size);                       \
        client.sin_family = AF_INET;                         \
        client.sin_port = htons(port);                       \
        client.sin_addr.s_addr = inet_addr(path);            \
        struct sockaddr* addr = (struct sockaddr*)&client;   \
        if (sendto(fd, data, length, 0, addr, size) == -1) { \
            close(fd);                                       \
            return false;                                    \
        }                                                    \
        close(fd);                                           \
    } while (0)

#elif defined(_MSC_VER)
//
// Microsoft Windows
//
#include <WinSock2.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable : 4996)
#define UDP_SEND_DATAGRAM(data, length, path, port)                       \
    do {                                                                  \
        WSADATA wsaData;                                                  \
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {                  \
            return false;                                                 \
        }                                                                 \
        struct sockaddr_in client;                                        \
        SOCKET fd = socket(AF_INET, SOCK_DGRAM, 0);                       \
        if (fd == INVALID_SOCKET)                                         \
            return false;                                                 \
        int size = static_cast<int>(sizeof(client));                      \
        std::memset(&client, 0, size);                                    \
        client.sin_family = AF_INET;                                      \
        client.sin_port = htons(port);                                    \
        client.sin_addr.s_addr = inet_addr(path);                         \
        struct sockaddr* a = reinterpret_cast<struct sockaddr*>(&client); \
        if (sendto(fd, reinterpret_cast<const char*>(data),               \
                static_cast<int>(length), 0, a, size)                     \
            == SOCKET_ERROR) {                                            \
            closesocket(fd);                                              \
            return false;                                                 \
        }                                                                 \
        closesocket(fd);                                                  \
    } while (0)

#else
//
// OS Unknown
//
#error "Well, sorry for your weird OS..."
#endif

////////////////////////////////////////////////////////////////
// UDS Support
//
#if defined(__linux__)
#define _DOGFOOD_UDS_SUPPORT

//
//     Linux
//
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#define UDS_SEND_DATAGRAM(data, length, path)                     \
    do {                                                          \
        struct sockaddr_un client;                                \
        int fd = socket(AF_UNIX, SOCK_DGRAM, 0);                  \
        if (fd == -1)                                             \
            return false;                                         \
        client.sun_family = AF_UNIX;                              \
        std::strcpy(client.sun_path, path);                       \
        int size = std::strlen(path) + sizeof(client.sun_family); \
        struct sockaddr* addr = (struct sockaddr*)&client;        \
        bind(fd, addr, size);                                     \
        if (sendto(fd, data, length, 0, addr, size) == -1) {      \
            close(fd);                                            \
            return false;                                         \
        }                                                         \
        close(fd);                                                \
    } while (0)

#endif

////////////////////////////////////////////////////////////////
// noexcept support
//
//
#if defined(__clang__)
#if __has_feature(cxx_noexcept)
#define _DOGFOOD_HAS_NOEXCEPT
#endif
#else
#if defined(__GXX_EXPERIMENTAL_CXX0X__) && __GNUC__ * 10 + __GNUC_MINOR__ >= 46 || defined(_MSC_FULL_VER) && _MSC_FULL_VER >= 190023026
#define _DOGFOOD_HAS_NOEXCEPT
#endif
#endif

#ifdef _DOGFOOD_HAS_NOEXCEPT
#define _DOGFOOD_NOEXCEPT noexcept
#else
#define _DOGFOOD_NOEXCEPT
#endif

namespace DogFood {

enum class Mode {
#if defined(_DOGFOOD_UDS_SUPPORT)
    UDS,
#endif
    UDP
};

using Configuration = std::tuple<Mode, std::string, int>;

////////////////////////////////////////////////////////////////
// Tags
//
//     Use a map of string->string for storing 'Key'->'Value'
//     pairs. If the 'Value' is empty, only the 'Key' is used
//
using Tags = std::vector<std::pair<std::string, std::string>>;

////////////////////////////////////////////////////////////////
// Type
//
//     The 'Type' of a DataDog 'Metric'
//
enum Type {
    Counter,
    Gauge,
    Timer,
    Histogram,
    Set
};

////////////////////////////////////////////////////////////////
// Priority
//
//     The 'Priority' of a DataDog 'Event'
//
enum class Priority {
    Low,
    Normal
};

////////////////////////////////////////////////////////////////
// Alert
//
//     The 'Alert' type of a DataDog 'Event'
//
enum class Alert {
    Info,
    Success,
    Warning,
    Error
};

////////////////////////////////////////////////////////////////
// Status
//
//     The 'Status' of a DataDog 'Service Check'
//
enum class Status {
    Ok,
    Warning,
    Critical,
    Unknown
};

Configuration DefaultConfiguration();
std::optional<Configuration> Configure(const std::string& path);
inline bool ValidatePort(const int _port);

std::string
Metric(
    const std::string& _name,
    const double _value,
    const Type _type,
    const double _rate = 1.0,
    const Tags& _tags = Tags())
    _DOGFOOD_NOEXCEPT;

bool Send(
    const std::string& _datagram,
    const Configuration& _configuration = DefaultConfiguration());

} // namespace DogFood
