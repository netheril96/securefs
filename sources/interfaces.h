#pragma once

#include "utils.h"

#include <exception>
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <string>

#define DISABLE_COPY_MOVE(cls)                                                                     \
    cls(const cls&) = delete;                                                                      \
    cls(cls&&) = delete;                                                                           \
    cls& operator=(const cls&) = delete;                                                           \
    cls& operator=(cls&&) = delete;

namespace securefs
{
/**
 * Base classes for byte streams.
 **/
class StreamBase
{
public:
    StreamBase() {}
    virtual ~StreamBase() {}
    DISABLE_COPY_MOVE(StreamBase);

    /**
     * Returns the number of bytes actually read into the buffer `output`.
     * Always read in full unless beyond the end, i.e., offset + length > size.
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

    /**
     * Sparse streams can be extended with zeros in constant time.
     * Some algorithms may be specialized on sparse streams.
     */
    virtual bool is_sparse() const noexcept { return false; }
};

/**
 * Interfaces for any class that supports a fixed size buffer for storing headers for files
 */
class HeaderBase
{
public:
    HeaderBase() {}
    virtual ~HeaderBase() {}
    DISABLE_COPY_MOVE(HeaderBase);

    virtual length_type header_length() const noexcept = 0;
    virtual void read_header(void* output, length_type length) = 0;
    virtual void write_header(const void* input, length_type length) = 0;
};

/**
 * Base classes for files, directories and symbolic links.
 * It is empty, only a marker for types.
 **/
class FileBase
{
    FileBase() {}
    virtual ~FileBase() {}
    DISABLE_COPY_MOVE(FileBase);
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
