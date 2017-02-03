#include "logger.h"
#include "myutils.h"
#include "platform.h"

#include <stdarg.h>
#include <stdio.h>

#ifdef WIN32
#include <Windows.h>
#include <time.h>

static void flockfile(FILE*) {}
static void funlockfile(FILE*) {}

static size_t current_thread_id(void) { return GetCurrentThreadId(); }
#else
#include <pthread.h>
static size_t current_thread_id(void) { return reinterpret_cast<size_t>(pthread_self()); }
#endif

static const char* WARNING_COLOR = "\033[1;30m";
static const char* ERROR_COLOR = "\033[1;31m";
static const char* DEFAULT_COLOR = "\033[0;39m";

namespace securefs
{
void Logger::vlog(LoggingLevel level, const char* format, va_list args) noexcept
{
    if (!m_fp || level < this->get_level())
        return;

    struct fuse_timespec now;
    OSService::get_current_time(now);
    struct tm tm;

#ifndef WIN32
    gmtime_r(&now.tv_sec, &tm);
#else
    time_t now_in_seconds = now.tv_sec;
    gmtime_s(&tm, &now_in_seconds);
#endif

    flockfile(m_fp);

#ifndef WIN32
    if (m_fp == stderr)
    {
        switch (level)
        {
        case kLogWarning:
            fputs(WARNING_COLOR, m_fp);
            break;
        case kLogError:
            fputs(ERROR_COLOR, m_fp);
            break;
        default:
            break;
        }
    }
#endif

    fprintf(m_fp,
            "[%s] [0x%zx] [%d-%02d-%02d %02d:%02d:%02d.%09d UTC]    ",
            stringify(level),
            current_thread_id(),
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            static_cast<int>(now.tv_nsec));
    vfprintf(m_fp, format, args);

#ifndef WIN32
    if (m_fp == stderr && (level == kLogWarning || level == kLogError))
    {
        fputs(DEFAULT_COLOR, m_fp);
    }
#endif

    putc('\n', m_fp);
    fflush(m_fp);
    funlockfile(m_fp);
}

void Logger::log(LoggingLevel level, const char* format, ...) noexcept
{
    if (!m_fp || level < this->get_level())
        return;
    va_list args;
    va_start(args, format);
    vlog(level, format, args);
    va_end(args);
}

Logger::Logger(FILE* fp, bool close_on_exit)
    : m_level(kLogInfo), m_fp(fp), m_close_on_exit(close_on_exit)
{
}

Logger::~Logger()
{
    if (m_close_on_exit)
        fclose(m_fp);
}

Logger* Logger::create_null_logger() { return new Logger(nullptr, false); }

Logger* Logger::create_stderr_logger() { return new Logger(stderr, false); }

Logger* Logger::create_file_logger(const std::string& path)
{
#ifdef WIN32
    FILE* fp = _wfopen(widen_string(path).c_str(), L"a");
#else
    FILE* fp = fopen(path.c_str(), "a");
#endif
    if (!fp)
        throwPOSIXException(errno, path);
    return new Logger(fp, true);
}

std::unique_ptr<Logger> global_logger(Logger::create_stderr_logger());
}
