#pragma once

#include "format.h"
#include "myutils.h"

#include <errno.h>
#include <exception>
#include <stdint.h>
#include <string.h>
#include <string>
#include <utility>

namespace securefs
{
struct StackTraceElement
{
    std::string object_name, function_name;
};
typedef std::vector<StackTraceElement> StackTrace;
bool getStackTrace(StackTrace& output, int num_ignore) noexcept;

enum class ExceptionLevel
{
    Debug = 0,
    Warn = 1,
    Error = 2,
    Fatal = 3
};

class ExceptionBase : public std::exception
{
private:
    mutable std::string m_cached_msg;
    // Mutable fields are not thread safe in `const` functions.
    // But who accesses exception objects concurrently anyway?

public:
    virtual const char* type_name() const noexcept = 0;
    virtual std::string message() const = 0;
    virtual int error_number() const noexcept { return EPERM; }
    virtual ExceptionLevel level() const noexcept = 0;
    const char* what() const noexcept final override
    {
        if (m_cached_msg.empty())
        {
            try
            {
                message().swap(m_cached_msg);
            }
            catch (...)
            {
                return type_name();
            }
        }
        return m_cached_msg.c_str();
    }
};

class CommonException : public ExceptionBase
{
    ExceptionLevel level() const noexcept override { return ExceptionLevel::Warn; }
};

class SeriousException : public ExceptionBase
{
private:
    StackTrace m_traces;

public:
    explicit SeriousException() { getStackTrace(m_traces, 1); }
    ExceptionLevel level() const noexcept override { return ExceptionLevel::Error; }
    const StackTrace& stack_trace() const noexcept { return m_traces; }
};

class FatalException : public SeriousException
{
    ExceptionLevel level() const noexcept override { return ExceptionLevel::Fatal; }
};

class NotImplementedException : public SeriousException
{
private:
    const char* m_func;

public:
    explicit NotImplementedException(const char* func_name) : m_func(func_name) {}

    std::string message() const override
    {
        return fmt::format("Function/method {} of this instance is not implemented", m_func);
    }

    const char* type_name() const noexcept override { return "NotImplementedException"; }
};

class NullPointerException : public FatalException
{
private:
    const char* m_func;
    const char* m_file;
    int m_line;

public:
    explicit NullPointerException(const char* func, const char* file, int line)
        : m_func(func), m_file(file), m_line(line)
    {
    }

    const char* type_name() const noexcept override { return "NullPointerException"; }

    std::string message() const override
    {
        const char* format = "Unexpected null pointer in function \"{}\" at {}:{}";
        return fmt::format(format, m_func, m_file, m_line);
    }
};

#define NULL_EXCEPT() throw securefs::NullPointerException(__PRETTY_FUNCTION__, __FILE__, __LINE__)

class UnreachableCodeException : public FatalException
{
private:
    const char* m_func;
    const char* m_file;
    int m_line;

public:
    explicit UnreachableCodeException(const char* func, const char* file, int line)
        : m_func(func), m_file(file), m_line(line)
    {
    }

    const char* type_name() const noexcept override { return "UnreachableCodeException"; }

    std::string message() const override
    {
        const char* format = "Unreachable code executed in function \"{}\" at {}:{}";
        return fmt::format(format, m_func, m_file, m_line);
    }
};

#define UNREACHABLE()                                                                              \
    throw securefs::UnreachableCodeException(__PRETTY_FUNCTION__, __FILE__, __LINE__)

class OSException : public CommonException
{
private:
    int m_errno;

public:
    explicit OSException(int errc) : m_errno(errc) {}

    const char* type_name() const noexcept override { return "OSException"; }

    int error_number() const noexcept override { return m_errno; }

    std::string message() const override { return sane_strerror(m_errno); }
};

class POSIXException : public SeriousException
{
private:
    int m_errno;
    std::string m_msg;

public:
    explicit POSIXException(int errc, std::string msg) : m_errno(errc), m_msg(std::move(msg)) {}

    const char* type_name() const noexcept override { return "POSIXException"; }

    int error_number() const noexcept override { return m_errno; }

    std::string message() const override { return sane_strerror(m_errno) + " # " + m_msg; }
};

class VerificationException : public SeriousException
{
};

class InvalidFormatException : public SeriousException
{
};

class InvalidArgumentException : public SeriousException
{
private:
    std::string m_msg;

public:
    explicit InvalidArgumentException(std::string why) { m_msg.swap(why); }

    const char* type_name() const noexcept override { return "InvalidArgumentException"; }

    std::string message() const override { return m_msg; }

    int error_number() const noexcept override { return EINVAL; }
};

class CorruptedMetaDataException : public InvalidFormatException
{
private:
    id_type m_id;
    const char* m_reason;

public:
    explicit CorruptedMetaDataException(const id_type& id, const char* reason) : m_reason(reason)
    {
        memcpy(m_id.data(), id.data(), id.size());
    }

    const char* type_name() const noexcept override { return "CorruptedMetaDataException"; }

    std::string message() const override
    {
        return fmt::format(
            "Metadata for ID {} is corrupted ({})", hexify(m_id.data(), m_id.size()), m_reason);
    }
};

class MessageVerificationException : public VerificationException
{
private:
    id_type m_id;
    offset_type m_off;

public:
    explicit MessageVerificationException(const id_type& id, offset_type off) : m_off(off)
    {
        memcpy(m_id.data(), id.data(), id.size());
    }
    const char* type_name() const noexcept override { return "MessageVerificationException"; }

    std::string message() const override
    {
        return fmt::format("Message for ID {} at offset {} does not match the checksum",
                           hexify(m_id.data(), m_id.size()),
                           m_off);
    }
};

class XattrVerificationException : public VerificationException
{
private:
    id_type m_id;
    std::string m_name;

public:
    explicit XattrVerificationException(const id_type& id, std::string name)
    {
        memcpy(m_id.data(), id.data(), id.size());
        m_name.swap(name);
    }

    const char* type_name() const noexcept override { return "XattrVerificationException"; }

    std::string message() const override
    {
        return fmt::format("Extended attribute for ID {} and name \"{}\" has wrong checksum",
                           hexify(m_id.data(), m_id.size()),
                           m_name);
    }
};

class StreamTooLongException : public SeriousException
{
private:
    int64_t m_max_size;
    int64_t m_size;

public:
    explicit StreamTooLongException(int64_t max_size, int64_t size)
        : m_max_size(max_size), m_size(size)
    {
    }
    const char* type_name() const noexcept override { return "StreamTooLongException"; }
    std::string message() const override
    {
        return fmt::format("Operation on stream at point {}, which exceeds its maximum size {}",
                           m_size,
                           m_max_size);
    }
    int error_number() const noexcept override { return EFBIG; }
};
}
