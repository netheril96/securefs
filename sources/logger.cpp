#include "logger.h"
#include "myutils.h"

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

namespace securefs
{

void Logger::vlog(LoggingLevel level, const char* format, va_list args) noexcept
{
    if (level < this->get_level())
        return;

    struct timeval now;
    gettimeofday(&now, nullptr);
    struct tm tm;
    gmtime_r(&now.tv_sec, &tm);
    fprintf(m_fp,
            "[%s] [%d-%02d-%02dT%02d:%02d:%02d.%06dZ]    ",
            stringify(level),
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            now.tv_usec);

    vfprintf(m_fp, format, args);
    putc('\n', m_fp);
    fflush(m_fp);
}

void Logger::log(LoggingLevel level, const char* format, ...) noexcept
{
    if (level < this->get_level())
        return;
    va_list args;
    va_start(args, format);
    vlog(level, format, args);
    va_end(args);
}
}
