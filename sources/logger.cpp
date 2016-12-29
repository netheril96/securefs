#include "logger.h"
#include "myutils.h"
#include "platform.h"

#include <stdarg.h>
#include <stdio.h>

#ifdef WIN32
#include <Windows.h>
#endif


namespace securefs
{
void Logger::vlog(LoggingLevel level, const char* format, va_list args) noexcept
{
    if (level < this->get_level())
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

    int size1 = snprintf(buffer.data(),
                         buffer.size(),
                         "[%s] [%d-%02d-%02d %02d:%02d:%02d.%09d UTC]    ",
                         stringify(level),
                         tm.tm_year + 1900,
                         tm.tm_mon + 1,
                         tm.tm_mday,
                         tm.tm_hour,
                         tm.tm_min,
                         tm.tm_sec,
                         static_cast<int>(now.tv_nsec));

    if (size1 < 0 || static_cast<size_t>(size1) >= buffer.size())
        return;

    int size2 = vsnprintf(buffer.data() + size1, buffer.size() - size1, format, args);
    if (size2 < 0)
        return;

    int total_size = size1 + size2;
    if (static_cast<size_t>(total_size) < buffer.size())
        buffer[total_size] = '\n';
    else
        buffer.back() = '\n';

#ifdef WIN32
	if ((m_fd == 1 || m_fd == 2) && securefs::OSService::isatty(m_fd))
	{
		wchar_t wide_buffer[8000];
		int sz = MultiByteToWideChar(CP_UTF8, 0, buffer.data(), 
			std::min<int>(buffer.size(), total_size + 1), wide_buffer, 8000);
		HANDLE hd = GetStdHandle(m_fd == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
		WriteConsoleW(hd, wide_buffer, sz, nullptr, nullptr);
		return;
	}
#endif

    (void)write(m_fd, buffer.data(), std::min<int>(buffer.size(), total_size + 1));
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
