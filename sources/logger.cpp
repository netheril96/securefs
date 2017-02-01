#include "logger.h"
#include "myutils.h"
#include "platform.h"

#include <stdarg.h>
#include <stdio.h>

#ifdef WIN32
#include <Windows.h>

static void flockfile(FILE*) {}
static void funlockfile(FILE*) {}

static size_t current_thread_id(void) { return GetCurrentThreadId(); }
#else
#include <pthread.h>
static size_t current_thread_id(void) { return reinterpret_cast<size_t>(pthread_self()); }
#endif

namespace securefs
{
void Logger::vlog(LoggingLevel level, const char* format, va_list args) noexcept
{
    if (!m_fp || level < this->get_level())
        return;

    struct timespec now;
    OSService::get_current_time(now);
    struct tm tm;

#ifndef WIN32
    gmtime_r(&now.tv_sec, &tm);
#else
    time_t now_in_seconds = now.tv_sec;
    gmtime_s(&tm, &now_in_seconds);
#endif

    flockfile(m_fp);
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
    FILE* fp = fopen(path.c_str(), "a");
    if (!fp)
        throwPOSIXException(errno, path);
    return new Logger(fp, true);
}

std::unique_ptr<Logger> global_logger(Logger::create_stderr_logger());
}
