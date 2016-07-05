#pragma once
#include "exceptions.h"
#include "streams.h"

#include <cstdarg>
#include <stddef.h>
#include <stdio.h>
#include <string>

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
private:
    LoggingLevel m_level;
    FILE* m_fp;
    bool m_close_on_exit;

public:
    explicit Logger(LoggingLevel level, FILE* fp, bool close_on_exit)
        : m_level(level), m_fp(fp), m_close_on_exit(close_on_exit)
    {
    }

    void
    vlog(LoggingLevel level, const char* format, va_list args) noexcept;

    void log(LoggingLevel level, const char* format, ...) noexcept
        __attribute__((format(printf, 3, 4)));

    LoggingLevel get_level() const noexcept { return m_level; }
    void set_level(LoggingLevel lvl) noexcept { m_level = lvl; }

    ~Logger()
    {
        if (m_close_on_exit)
            fclose(m_fp);
    }
};
}