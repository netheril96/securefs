#include "logger.h"
#include "myutils.h"

#include <stdarg.h>
#include <stdio.h>

#include <fcntl.h>
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

    int size1 = snprintf(buffer.data(),
                         buffer.size(),
                         "[%s] [%d-%02d-%02dT%02d:%02d:%02d.%06dZ]    ",
                         stringify(level),
                         tm.tm_year + 1900,
                         tm.tm_mon + 1,
                         tm.tm_mday,
                         tm.tm_hour,
                         tm.tm_min,
                         tm.tm_sec,
                         static_cast<int>(now.tv_usec));

    if (size1 < 0 || static_cast<size_t>(size1) >= buffer.size())
        return;

    int size2 = vsnprintf(buffer.data() + size1, buffer.size() - size1, format, args);
    if (size2 < 0)
        return;

    size_t total_size = size1 + size2;
    if (total_size < buffer.size())
        buffer[total_size] = '\n';
    else
        buffer.back() = '\n';

    (void)write(m_fd, buffer.data(), std::min<size_t>(buffer.size(), total_size + 1));
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

Logger::Logger(LoggingLevel level, int fd, bool close_on_exit)
    : m_level(level), m_fd(fd), m_close_on_exit(close_on_exit), buffer(4000)
{
}

Logger::~Logger()
{
    if (m_close_on_exit)
        ::close(m_fd);
}
}
