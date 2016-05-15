#include "logger.h"
#include "myutils.h"

#include <format.h>

#include <thread>

namespace securefs
{
void Logger::log(LoggingLevel level, const std::string& msg, const char* func) noexcept
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
}
