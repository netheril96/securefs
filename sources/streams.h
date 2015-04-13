#pragma once
#include "interfaces.h"
#include "exceptions.h"

#include <memory>
#include <utility>

#include <unistd.h>
#include <sys/stat.h>

namespace securefs
{
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
};

std::pair<std::shared_ptr<CryptStream>, std::shared_ptr<HeaderBase>>
make_cryptstream_aes_gcm(std::shared_ptr<StreamBase> data_stream,
                         std::shared_ptr<StreamBase> meta_stream,
                         std::shared_ptr<const SecureParam> param,
                         bool check);
}
