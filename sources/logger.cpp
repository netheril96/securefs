#include "logger.h"
#include "exceptions.h"
#include "myutils.h"
#include "platform.h"

#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>
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
Logger::Logger(FILE* fp, bool close_on_exit)
    : m_level(kLogInfo), m_fp(fp), m_close_on_exit(close_on_exit)
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
        case kLogWarning:
            m_console_color->use(Colour::Warning);
            break;
        case kLogError:
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
    if (m_console_color && (level == kLogWarning || level == kLogError))
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
    return new Logger(fp, true);
}

Logger* global_logger = Logger::create_stderr_logger();
}    // namespace securefs
