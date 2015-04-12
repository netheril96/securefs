#pragma once

#include "def.h"

#include <exception>
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <string>

namespace securefs
{
/**
 * Base classes for most abstract classes and interfaces.
 * The utility it provides is deleted copy and move ctors.
 **/
class AbstractBase
{
public:
    explicit AbstractBase() {}
    virtual ~AbstractBase() {}
    AbstractBase(const AbstractBase&) = delete;
    AbstractBase(AbstractBase&&) = delete;
    AbstractBase& operator=(const AbstractBase&) = delete;
    AbstractBase& operator=(AbstractBase&&) = delete;
};

/**
 * Base classes for byte streams.
 **/
class StreamBase : public AbstractBase
{
public:
    /**
     * Returns the number of bytes actually read into the buffer `output`.
     **/
    virtual length_type read(void* output, offset_type offset, length_type length) = 0;

    /**
     * Write must always succeed as a whole or throw an exception otherwise.
     * If the offset is beyond the end of the stream, the gap should be filled with zeros.
     **/
    virtual void write(const void* input, offset_type offset, length_type length) = 0;

    virtual length_type size() const = 0;

    virtual void flush() = 0;

    /**
     * Similar to ftruncate().
     * Discard extra data when shrinking, zero-fill when extending.
     **/
    virtual void resize(length_type) = 0;
};

/**
 * Base classes for files, directories and symbolic links.
 * It is empty, only a marker for types.
 **/
class FileBase : public AbstractBase
{
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
    const char* what() const noexcept final override
    {
        if (m_cached_msg.empty())
            message().swap(m_cached_msg);
        return m_cached_msg.c_str();
    }
};
}
