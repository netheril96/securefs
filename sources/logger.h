#pragma once
#include "exceptions.h"
#include "streams.h"

#include <cstdarg>
#include <stddef.h>
#include <stdio.h>
#include <string>

namespace securefs
{
typedef ExceptionLevel LoggingLevel;

inline const char* stringify(LoggingLevel lvl)
{
    switch (lvl)
    {
    case LoggingLevel::Debug:
        return "DEBUG";
    case LoggingLevel::Warn:
        return "WARN";
    case LoggingLevel::Error:
        return "ERROR";
    case LoggingLevel::Fatal:
        return "FATAL";
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

    void log_old(LoggingLevel level, const std::string& msg, const char* func) noexcept;

    void
    vlog(LoggingLevel level, const StackTrace* trace, const char* format, va_list args) noexcept;

    void log(LoggingLevel level, const StackTrace* trace, const char* format, ...) noexcept
        __attribute__((format(printf, 4, 5)));

    LoggingLevel get_level() const noexcept { return m_level; }
    void set_level(LoggingLevel lvl) noexcept { m_level = lvl; }

    ~Logger()
    {
        if (m_close_on_exit)
            fclose(m_fp);
    }
};
}