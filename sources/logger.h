#pragma once
#include "platform.h"

#include <absl/functional/function_ref.h>
#include <absl/strings/str_format.h>

#include <cstdint>
#include <memory>
#include <stdio.h>
#include <string>

namespace securefs
{
enum class LoggingLevel : unsigned char
{
    kLogTrace = 0,
    kLogVerbose = 1,
    kLogInfo = 2,
    kLogWarning = 3,
    kLogError = 4
};

const char* stringify(LoggingLevel lvl);

namespace trace
{
    class FuseTracer;
}

class FuseTracer;

class Logger
{
    DISABLE_COPY_MOVE(Logger)
    friend class FuseTracer;
    friend class trace::FuseTracer;

private:
    LoggingLevel m_level;
    FILE* m_fp;
    std::unique_ptr<ConsoleColourSetter> m_console_color;
    bool m_close_on_exit;

    explicit Logger(FILE* fp, bool close_on_exit);

    void prelog(LoggingLevel level, const char* funcsig, int lineno) noexcept;
    void postlog(LoggingLevel level) noexcept;

    void log_v2(LoggingLevel level,
                const char* funcsig,
                int lineno,
                absl::FunctionRef<void(std::FILE*)> output_fun);

public:
    static Logger* create_stderr_logger();
    static Logger* create_file_logger(const std::string& path);
    static Logger* create_logger_from_native_handle(int64_t native_handle);
    int64_t get_native_handle() const;

    template <typename... Args>
    void log_v2(LoggingLevel level,
                const char* funcsig,
                int lineno,
                const absl::FormatSpec<Args...>& fms,
                Args&&... args) noexcept
    {
        log_v2(level,
               funcsig,
               lineno,
               [&](std::FILE* fp) { absl::FPrintF(fp, fms, std::forward<Args>(args)...); });
    }

    LoggingLevel get_level() const noexcept { return m_level; }
    void set_level(LoggingLevel lvl) noexcept { m_level = lvl; }

    ~Logger();
};

extern Logger* global_logger;

#ifdef _MSC_VER
#define FULL_FUNCTION_NAME __FUNCSIG__
#else
#define FULL_FUNCTION_NAME __PRETTY_FUNCTION__
#endif

#define GENERIC_LOG(log_level, ...)                                                                \
    do                                                                                             \
    {                                                                                              \
        using securefs::global_logger;                                                             \
        if (global_logger && global_logger->get_level() <= log_level)                              \
        {                                                                                          \
            global_logger->log_v2(log_level, FULL_FUNCTION_NAME, __LINE__, __VA_ARGS__);           \
        }                                                                                          \
    } while (0)
#define TRACE_LOG(...) GENERIC_LOG(securefs::LoggingLevel::kLogTrace, __VA_ARGS__)
#define VERBOSE_LOG(...) GENERIC_LOG(securefs::LoggingLevel::kLogVerbose, __VA_ARGS__)
#define INFO_LOG(...) GENERIC_LOG(securefs::LoggingLevel::kLogInfo, __VA_ARGS__)
#define WARN_LOG(...) GENERIC_LOG(securefs::LoggingLevel::kLogWarning, __VA_ARGS__)
#define ERROR_LOG(...) GENERIC_LOG(securefs::LoggingLevel::kLogError, __VA_ARGS__)
}    // namespace securefs
