#pragma once
#include "interfaces.h"

#include "format.h"

#include <string>
#include <exception>
#include <utility>
#include <string.h>

namespace securefs
{
class CommonException : public ExceptionBase
{
};

class SeriousException : public ExceptionBase
{
};

class FatalException : public ExceptionBase
{
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

    std::string message() const override
    {
        // strerror() is not thread safe
        // strerror_r() is different on different platforms
        // Fall back to the "deprecated" but only sane way to stringify the errno
        if (m_errno >= 0 && m_errno < sys_nerr)
            return sys_errlist[m_errno];
        return fmt::format("Unknown error code {}", m_errno);
    }
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
    explicit MessageVerificationException(const id_type& id, offset_type off) : m_off(off) {}
    const char* type_name() const noexcept override { return "MessageVerificationException"; }

    std::string message() const override
    {
        return fmt::format("Message for ID {} at offset {} does not match the checksum",
                           hexify(m_id.data(), m_id.size()),
                           m_off);
    }
};
}
