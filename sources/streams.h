#pragma once
#include "exceptions.h"
#include "utils.h"

#include <memory>
#include <utility>

#include <unistd.h>
#include <sys/stat.h>

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

    /**
     * Methods implemented by file streams or their wrappers.
     */
    virtual void stat(struct stat*) { throw NotImplementedException(__PRETTY_FUNCTION__); }

    /**
     * Methods implemented by file streams or their wrappers.
     */
    virtual void fsync() { throw NotImplementedException(__PRETTY_FUNCTION__); }

    /**
     * Certain streams are more efficient when reads and writes are aligned to blocks
     */
    virtual length_type optimal_block_size() const noexcept { return 1; }

    /**
     * Cryptographic streams may have this for authentication purposes
     */
    virtual const id_type& get_id() const { throw NotImplementedException(__PRETTY_FUNCTION__); }
};

/**
 * Interface that supports a fixed size buffer to store headers for files
 */
class HeaderBase
{
public:
    HeaderBase() {}
    virtual ~HeaderBase() {}
    DISABLE_COPY_MOVE(HeaderBase);

    virtual length_type max_header_length() const noexcept = 0;

    /**
     * Returns: true if read in full, false if no header is present.
     * Never reads in part.
     */
    virtual bool read_header(void* output, length_type length) = 0;

    /**
     * Always write in full.
     */
    virtual void write_header(const void* input, length_type length) = 0;
    virtual void flush_header() = 0;
};

class POSIXFileStream : public StreamBase
{
private:
    int m_fd;
    length_type m_size;

public:
    explicit POSIXFileStream(int fd) : m_fd(fd)
    {
        if (fd < 0)
            throw OSException(EBADF);
        struct stat st;
        int rc = ::fstat(m_fd, &st);
        if (rc < 0)
            throw OSException(errno);
        m_size = st.st_size;
    }

    ~POSIXFileStream() { ::close(m_fd); }

    length_type read(void* output, offset_type offset, length_type length) override
    {
        auto rc = ::pread(m_fd, output, length, offset);
        if (rc < 0)
            throw OSException(errno);
        return rc;
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        auto rc = ::pwrite(m_fd, input, length, offset);
        if (rc < 0)
            throw OSException(errno);
        if (static_cast<length_type>(rc) != length)
            throw OSException(EIO);
        if (offset + length > m_size)
            m_size = offset + length;
    }

    void flush() override {}

    void resize(length_type new_length) override
    {
        auto rc = ::ftruncate(m_fd, new_length);
        if (rc < 0)
            throw OSException(errno);
        m_size = new_length;
    }

    length_type size() const override { return m_size; }

    bool is_sparse() const noexcept override { return true; }

    void stat(struct stat* st) override
    {
        int rc = ::fstat(m_fd, st);
        if (rc < 0)
            throw OSException(errno);
    }

    void fsync() override
    {
        int rc = ::fsync(m_fd);
        if (rc < 0)
            throw OSException(errno);
    }
};

std::shared_ptr<StreamBase> make_stream_hmac(std::shared_ptr<const SecureParam> param,
                                             std::shared_ptr<StreamBase> stream,
                                             bool check);

/**
 * Base classes for streams that encrypt and decrypt data transparently
 * The transformation is done in blocks,
 * and must always output data of the same length as input.
 *
 * Subclasses should use additional storage, such as another stream, to store IVs and MACs.
 *
 * The CryptStream supports sparse streams if the subclass can tell whether all zero block
 * are ciphertext or sparse parts of the underlying stream.
 */
class CryptStream : public StreamBase
{
protected:
    std::shared_ptr<StreamBase> m_stream;
    const length_type m_block_size;

    // Both encrypt/decrypt should not change the length of the block.
    // input/output may alias.
    virtual void
    encrypt(offset_type block_number, const void* input, void* output, length_type length) = 0;

    virtual void
    decrypt(offset_type block_number, const void* input, void* output, length_type length) = 0;

private:
    length_type read_block(offset_type block_number, void* output);
    length_type
    read_block(offset_type block_number, void* output, offset_type begin, offset_type end);

    void write_block(offset_type block_number, const void* input, length_type length);
    void read_then_write_block(offset_type block_number,
                               const void* input,
                               offset_type begin,
                               offset_type end);

    void unchecked_write(const void* input, offset_type offset, length_type length);
    void zero_fill(offset_type offset, length_type length);

public:
    explicit CryptStream(std::shared_ptr<StreamBase> stream, length_type block_size)
        : m_stream(std::move(stream)), m_block_size(block_size)
    {
        if (!m_stream)
            NULL_EXCEPT();
        if (m_block_size < 1)
            throw InvalidArgumentException("Too small block size");
    }

    length_type read(void* output, offset_type offset, length_type length) override;
    void write(const void* input, offset_type offset, length_type length) override;
    void flush() override { m_stream->flush(); }
    length_type size() const override { return m_stream->size(); }
    void resize(length_type new_length) override;
    void stat(struct stat* st) override { return m_stream->stat(st); }
    void fsync() override { return m_stream->fsync(); }
    length_type optimal_block_size() const noexcept override { return m_block_size; }
};

/**
 * AESGCMCryptStream is both a CryptStream and a HeaderBase.
 *
 * Returns a pair because the client does not need to know whether the two interfaces are
 * implemented by the same class.
 */
std::pair<std::shared_ptr<CryptStream>, std::shared_ptr<HeaderBase>>
make_cryptstream_aes_gcm(std::shared_ptr<StreamBase> data_stream,
                         std::shared_ptr<StreamBase> meta_stream,
                         std::shared_ptr<const SecureParam> param,
                         bool check);
}
