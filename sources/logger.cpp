#include "logger.h"
#include "utils.h"

#include <format.h>

#include <thread>

#include <sys/time.h>

namespace securefs
{
void Logger::log(LoggingLevel level,
                 const std::string& msg,
                 const char* func,
                 const char* file,
                 int line) noexcept
{
    struct timeval now;
    (void)gettimeofday(&now, nullptr);
    try
    {
        auto full_msg = fmt::format("[{}] [{}] [{}] [{}:{} {}]      {}\n",
                                    stringify(get_level()),
                                    format_current_time(),
                                    std::this_thread::get_id(),
                                    file,
                                    line,
                                    func,
                                    msg);
        append(full_msg.data(), full_msg.size());
    }
    catch (...)
    {
        // Cannot handle errors in logging
    }
}
}
