#pragma once
#include "exceptions.h"
#include "streams.h"

#include <cstdarg>
#include <stddef.h>
#include <stdio.h>
#include <string>
#include <vector>

namespace securefs
{
enum class LoggingLevel
{
    VERBOSE = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3
};

inline const char* stringify(LoggingLevel lvl)
{
    switch (lvl)
    {
    case LoggingLevel::VERBOSE:
        return "VERBOSE";
    case LoggingLevel::WARNING:
        return "WARNING";
    case LoggingLevel::ERROR:
        return "ERROR";
    case LoggingLevel::INFO:
        return "INFO";
    default:
        return "UNKNOWN";
    }
}

class Logger
{
    DISABLE_COPY_MOVE(Logger);

private:
    LoggingLevel m_level;
    int m_fd;
    bool m_close_on_exit;
    std::vector<char> buffer;

public:
    explicit Logger(LoggingLevel level, int fd, bool close_on_exit);

    void vlog(LoggingLevel level, const char* format, va_list args) noexcept;

    void log(LoggingLevel level, const char* format, ...) noexcept
        __attribute__((format(printf, 3, 4)));

    LoggingLevel get_level() const noexcept { return m_level; }
    void set_level(LoggingLevel lvl) noexcept { m_level = lvl; }

    ~Logger();
};
}