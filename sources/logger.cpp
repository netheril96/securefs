#include "logger.h"
#include "exceptions.h"
#include "myutils.h"
#include "platform.h"

#include <cerrno>
#include <corecrt_io.h>
#include <cstdint>
#include <errhandlingapi.h>
#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#include <time.h>

static void flockfile(FILE* fp) { _lock_file(fp); }
static void funlockfile(FILE* fp) { _unlock_file(fp); }

static const void* current_thread_id(void)
{
    return reinterpret_cast<const void*>(static_cast<uintptr_t>(GetCurrentThreadId()));
}
#else
#include <pthread.h>
static const void* current_thread_id(void) { return (void*)(pthread_self()); }
#endif

namespace securefs
{
const char* stringify(LoggingLevel lvl)
{
    switch (lvl)
    {
    case LoggingLevel::kLogTrace:
        return "Trace";
    case LoggingLevel::kLogVerbose:
        return "Verbose";
    case LoggingLevel::kLogInfo:
        return "Info";
    case LoggingLevel::kLogWarning:
        return "Warning";
    case LoggingLevel::kLogError:
        return "Error";
    }
    // This part should ideally not be reached if all enum values are handled.
    return "UNKNOWN";
}

Logger::Logger(FILE* fp, bool close_on_exit)
    : m_level(LoggingLevel::kLogInfo), m_fp(fp), m_close_on_exit(close_on_exit)
{
    m_console_color = ConsoleColourSetter::create_setter(m_fp);
}

void Logger::prelog(LoggingLevel level, const char* funcsig, int lineno) noexcept
{
    if (!m_fp || level < this->get_level())
        return;

    struct tm now;
    int now_ns = 0;
    OSService::get_current_time_in_tm(&now, &now_ns);

    flockfile(m_fp);
    if (m_console_color)
    {
        switch (level)
        {
        case LoggingLevel::kLogWarning:
            m_console_color->use(Colour::Warning);
            break;
        case LoggingLevel::kLogError:
            m_console_color->use(Colour::Error);
            break;
        default:
            break;
        }
    }

    fprintf(m_fp,
            "[%s] [%p] [%d-%02d-%02d %02d:%02d:%02d.%09d UTC] [%s:%d]    ",
            stringify(level),
            current_thread_id(),
            now.tm_year + 1900,
            now.tm_mon + 1,
            now.tm_mday,
            now.tm_hour,
            now.tm_min,
            now.tm_sec,
            now_ns,
            funcsig,
            lineno);
}

void Logger::postlog(LoggingLevel level) noexcept
{
    if (m_console_color && (level == LoggingLevel::kLogWarning || level == LoggingLevel::kLogError))
    {
        m_console_color->use(Colour::Default);
    }

    putc('\n', m_fp);
    fflush(m_fp);
    funlockfile(m_fp);
}

void Logger::log_v2(LoggingLevel level,
                    const char* funcsig,
                    int lineno,
                    absl::FunctionRef<void(std::FILE*)> output_fun)
{
    if (!m_fp || level < this->get_level())
        return;
    prelog(level, funcsig, lineno);
    DEFER(postlog(level));
    try
    {
        output_fun(m_fp);
    }
    catch (const std::exception& e)
    {
        absl::FPrintF(m_fp, "Logging itself throws exception: %s", e.what());
    }
}

Logger::~Logger()
{
    if (m_close_on_exit)
        fclose(m_fp);
}

Logger* Logger::create_stderr_logger() { return new Logger(stderr, false); }

Logger* Logger::create_file_logger(const std::string& path)
{
#ifdef _WIN32
    FILE* fp = _wfopen(widen_string(path).c_str(), L"a");
#else
    FILE* fp = fopen(path.c_str(), "a");
#endif
    if (!fp)
        THROW_POSIX_EXCEPTION(errno, path);
#ifdef _WIN32
    int fd = _fileno(fp);
    if (fd < 0)
    {
        THROW_POSIX_EXCEPTION(errno, "_fileno");
    }
    auto fileHandle = (HANDLE)_get_osfhandle(fd);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        throw_windows_exception(L"_get_osfhandle");
    }
    // Make sure a forked child can open the same logger.
    if (!SetHandleInformation(fileHandle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    {
        throw_windows_exception(L"SetHandleInformation");
    }
#endif
    return new Logger(fp, true);
}

Logger* Logger::create_logger_from_native_handle(int64_t native_handle)
{
#ifdef _WIN32
    int fd = _open_osfhandle(native_handle, _O_APPEND);
    if (fd < 0)
    {
        THROW_POSIX_EXCEPTION(errno, "_open_osfhandle");
    }
    auto fp = _fdopen(fd, "a");
    if (!fp)
    {
        THROW_POSIX_EXCEPTION(errno, "_fdopen");
    }
    return new Logger(fp, true);
#else
    auto fp = fdopen(static_cast<int>(native_handle), "a");
    if (!fp)
    {
        THROW_POSIX_EXCEPTION(errno, "fdopen");
    }
    return new Logger(fp, true);
#endif
}
int64_t Logger::get_native_handle() const
{
#ifdef _WIN32
    int fd = _fileno(m_fp);
    if (fd < 0)
    {
        THROW_POSIX_EXCEPTION(errno, "_fileno");
    }
    auto fileHandle = (HANDLE)_get_osfhandle(fd);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        throw_windows_exception(L"_get_osfhandle");
    }
    return reinterpret_cast<int64_t>(fileHandle);
#else
    return fileno(m_fp);
#endif
}

Logger* global_logger = Logger::create_stderr_logger();
}    // namespace securefs
