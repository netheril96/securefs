#pragma once
#include "exceptions.h"
#include "streams.h"

#include <memory>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string>

namespace securefs
{
enum LoggingLevel
{
    kLogTrace = 0,
    kLogDebug = 1,
    kLogInfo = 2,
    kLogWarning = 3,
    kLogError = 4
};

inline const char* stringify(LoggingLevel lvl)
{
    switch (lvl)
    {
    case kLogTrace:
        return "Trace";
    case kLogDebug:
        return "Debug";
    case kLogInfo:
        return "Info";
    case kLogWarning:
        return "Warning";
    case kLogError:
        return "Error";
    }
    return "UNKNOWN";
}

class Logger
{
    DISABLE_COPY_MOVE(Logger)

private:
    LoggingLevel m_level;
    FILE* m_fp;
    bool m_close_on_exit;

    explicit Logger(FILE* fp, bool close_on_exit);

public:
    static Logger* create_stderr_logger();
    static Logger* create_null_logger();
    static Logger* create_file_logger(const std::string& path);

    void vlog(LoggingLevel level, const char* format, va_list args) noexcept;
    void log(LoggingLevel level, const char* format, ...) noexcept
#ifndef WIN32
        __attribute__((format(printf, 3, 4)))
#endif
        ;

    LoggingLevel get_level() const noexcept { return m_level; }
    void set_level(LoggingLevel lvl) noexcept { m_level = lvl; }

    void trace(const char* format, ...) noexcept
    {
        if (!m_fp || get_level() > kLogTrace)
            return;

        va_list ap;
        va_start(ap, format);
        vlog(kLogTrace, format, ap);
        va_end(ap);
    }

    void debug(const char* format, ...) noexcept
    {
        if (!m_fp || get_level() > kLogDebug)
            return;

        va_list ap;
        va_start(ap, format);
        vlog(kLogDebug, format, ap);
        va_end(ap);
    }
    void info(const char* format, ...) noexcept
    {
        if (!m_fp || get_level() > kLogInfo)
            return;

        va_list ap;
        va_start(ap, format);
        vlog(kLogInfo, format, ap);
        va_end(ap);
    }
    void warn(const char* format, ...) noexcept
    {
        if (!m_fp || get_level() > kLogWarning)
            return;

        va_list ap;
        va_start(ap, format);
        vlog(kLogWarning, format, ap);
        va_end(ap);
    }
    void error(const char* format, ...) noexcept
    {
        if (!m_fp || get_level() > kLogError)
            return;

        va_list ap;
        va_start(ap, format);
        vlog(kLogError, format, ap);
        va_end(ap);
    }

    ~Logger();
};

extern std::unique_ptr<Logger> global_logger;
}
