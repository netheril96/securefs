#include "logger.h"
#include "myutils.h"

#include <format.h>

namespace securefs
{
void Logger::log_old(LoggingLevel level, const std::string& msg, const char* func) noexcept
{
    try
    {
        fmt::print(
            m_fp, "[{}] [{}] [{}]      {}\n", stringify(level), format_current_time(), func, msg);
    }
    catch (...)
    {
        // Cannot handle errors in logging
    }
}

void Logger::vlog(LoggingLevel level,
                  const StackTrace* trace,
                  const char* format,
                  va_list args) noexcept
{
    if (level < this->get_level())
        return;

    vfprintf(m_fp, format, args);
    putc('\n', m_fp);
    if (trace)
    {
        fprintf(m_fp, "%s", "    Stack trace:\n");
        for (auto&& e : *trace)
        {
            fprintf(m_fp, "    (%s)    %s\n", e.object_name.c_str(), e.function_name.c_str());
        }
    }
    fflush(m_fp);
}

void Logger::log(LoggingLevel level, const StackTrace* trace, const char* format, ...) noexcept
{
    va_list args;
    va_start(args, format);
    vlog(level, trace, format, args);
    va_end(args);
}
}
