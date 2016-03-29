#pragma once
#include "exceptions.h"
#include "streams.h"

#include <stddef.h>
#include <stdio.h>
#include <string>

namespace securefs
{
typedef ExceptionLevel LoggingLevel;

inline const char* stringify(LoggingLevel lvl)
{
    switch (lvl)
    {
    case LoggingLevel::DEBUG:
        return "DEBUG";
    case LoggingLevel::WARN:
        return "WARN";
    case LoggingLevel::ERROR:
        return "ERROR";
    case LoggingLevel::FATAL:
        return "FATAL";
    default:
        return "UNKNOWN";
    }
}

class Logger
{
protected:
    virtual void append(const void* data, size_t length) = 0;

private:
    LoggingLevel m_level;

public:
    explicit Logger(LoggingLevel level) : m_level(level) {}

    void log(LoggingLevel level,
             const std::string& msg,
             const char* func,
             const char* file,
             int line) noexcept;

    LoggingLevel get_level() const noexcept { return m_level; }
    void set_level(LoggingLevel lvl) noexcept { m_level = lvl; }

    virtual ~Logger() {}
};

class FileLogger : public Logger
{
private:
    FILE* m_fp;

public:
    explicit FileLogger(LoggingLevel lvl, FILE* fp) : Logger(lvl), m_fp(fp)
    {
        if (!fp)
            NULL_EXCEPT();
    }

protected:
    void append(const void* data, size_t length) noexcept override
    {
        fwrite(data, 1, length, m_fp);
        fflush(m_fp);
    }
};

class StreamLogger : public Logger
{
private:
    std::shared_ptr<StreamBase> m_stream;

public:
    explicit StreamLogger(LoggingLevel lvl, std::shared_ptr<StreamBase> stream)
        : Logger(lvl), m_stream(std::move(stream))
    {
    }

protected:
    void append(const void* data, size_t length) override
    {
        m_stream->write(data, m_stream->size(), length);
        m_stream->flush();
    }
};
}
