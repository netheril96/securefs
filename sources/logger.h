#pragma once
#include "exceptions.h"

#include <stddef.h>
#include <stdio.h>
#include <string>
#include <mutex>

namespace securefs
{

enum class LoggingLevel
{
    DEBUG = 0,
    WARN = 1,
    ERROR = 2,
    FATAL = 3
};

inline const char* stringify(LoggingLevel lvl)
{
    switch (lvl)
    {
    case LoggingLevel::DEBUG:
        return "DEBUG";
    case LoggingLevel::WARN:
        return "WARN";
    case LoggingLevel::ERROR:
        return "ERROR";
    case LoggingLevel::FATAL:
        return "FATAL";
    default:
        return "UNKNOWN";
    }
}

class Logger
{
protected:
    // Logging shall not throw exceptions, for we have nowhere to log logging errors
    virtual void append(const void* data, size_t length) noexcept = 0;

private:
    LoggingLevel m_level;

public:
    explicit Logger(LoggingLevel level) : m_level(level) {}

    void log(LoggingLevel level,
             const std::string& msg,
             const char* func,
             const char* file,
             int line) noexcept;

    LoggingLevel get_level() const noexcept { return m_level; }
    void set_level(LoggingLevel lvl) noexcept { m_level = lvl; }

    virtual ~Logger() {}
};

class FileLogger : public Logger
{
private:
    FILE* m_fp;
    std::mutex m_lock;

public:
    explicit FileLogger(LoggingLevel lvl, FILE* fp) : Logger(lvl), m_fp(fp)
    {
        if (!fp)
            NULL_EXCEPT();
    }

protected:
    void append(const void* data, size_t length) noexcept override
    {
        std::lock_guard<std::mutex> guard(m_lock);
        fwrite(data, 1, length, m_fp);
    }
};
}
