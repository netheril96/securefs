#pragma once
#include "exceptions.h"
#include "streams.h"

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

    void log(LoggingLevel level, const std::string& msg, const char* func) noexcept;

    LoggingLevel get_level() const noexcept { return m_level; }
    void set_level(LoggingLevel lvl) noexcept { m_level = lvl; }

    ~Logger()
    {
        if (m_close_on_exit)
            fclose(m_fp);
    }
};
}