#pragma once
#include "myutils.h"
#include "object.h"

#include <absl/container/fixed_array.h>
#include <memory>
#include <utility>
#include <variant>

namespace securefs
{

/**
 * Base classes for byte streams.
 **/
class StreamBase : public Object
{
public:
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
     * Certain streams are more efficient when reads and writes are aligned to blocks
     */
    virtual length_type optimal_block_size() const noexcept { return 1; }
};

/**
 * Interface that supports a fixed size buffer to store headers for files
 */
class HeaderBase
{
public:
    HeaderBase() {}
    virtual ~HeaderBase() {}
    DISABLE_COPY_MOVE(HeaderBase)

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

std::shared_ptr<StreamBase> make_stream_hmac(const key_type& key_,
                                             const id_type& id_,
                                             std::shared_ptr<StreamBase> stream,
                                             bool check);

class BlockBasedStream : public StreamBase
{
protected:
    length_type m_block_size;

protected:
    virtual length_type read_block(offset_type block_number, void* output) { return 0; }
    virtual void write_block(offset_type block_number, const void* input, length_type length) {}
    virtual length_type
    read_multi_blocks(offset_type start_block, offset_type end_block, void* output);
    virtual void write_multi_blocks(offset_type start_block,
                                    offset_type end_block,
                                    offset_type end_residue,
                                    const void* input)
    {
        for (offset_type b = start_block; b < end_block; ++b)
        {
            write_block(b, input, m_block_size);
            input = static_cast<const char*>(input) + m_block_size;
        }
        if (end_residue > 0)
        {
            write_block(end_block, input, end_residue);
        }
    }
    virtual void adjust_logical_size(length_type length) = 0;

private:
    struct ZeroFillTag
    {
    };

    void unchecked_write(std::variant<const void*, ZeroFillTag> input,
                         offset_type offset,
                         length_type length);
    void zero_fill(offset_type offset, length_type length);
    void unchecked_resize(length_type current_size, length_type new_size);

public:
    BlockBasedStream(length_type block_size) : m_block_size(block_size) {}
    ~BlockBasedStream() {}

    length_type read(void* output, offset_type offset, length_type length) override;
    void write(const void* input, offset_type offset, length_type length) override;
    void resize(length_type new_length) override;
    length_type optimal_block_size() const noexcept override { return m_block_size; }
};

/**
 * AESGCMCryptStream is both a Stream and a HeaderBase.
 *
 * Returns a pair because the client does not need to know whether the two interfaces are
 * implemented by the same class.
 */
std::pair<std::shared_ptr<StreamBase>, std::shared_ptr<HeaderBase>>
make_cryptstream_aes_gcm(std::shared_ptr<StreamBase> data_stream,
                         std::shared_ptr<StreamBase> meta_stream,
                         const key_type& data_key,
                         const key_type& meta_key,
                         const id_type& id_,
                         bool check,
                         unsigned block_size,
                         unsigned iv_size,
                         unsigned header_size = 32);

class PaddedStream final : public StreamBase
{
public:
    explicit PaddedStream(std::shared_ptr<StreamBase> delegate, unsigned padding_size);
    ~PaddedStream();

    length_type read(void* output, offset_type offset, length_type length) override
    {
        return m_delegate->read(output, offset + m_padding_size, length);
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        return m_delegate->write(input, offset + m_padding_size, length);
    }

    length_type size() const override
    {
        auto dsize = m_delegate->size();
        return dsize > m_padding_size ? dsize - m_padding_size : 0;
    }

    void flush() override { return m_delegate->flush(); }

    void resize(length_type size) override { return m_delegate->resize(size + m_padding_size); }

    bool is_sparse() const noexcept override { return m_delegate->is_sparse(); }

    length_type optimal_block_size() const noexcept override
    {
        return m_delegate->optimal_block_size();
    }

    unsigned padding_size() const noexcept { return m_padding_size; }

private:
    std::shared_ptr<StreamBase> m_delegate;
    unsigned m_padding_size;
};

class WriteCachedStream final : public StreamBase
{
public:
    WriteCachedStream(std::shared_ptr<StreamBase> delegate, length_type cache_size)
        : delegate_(std::move(delegate)), buffer_(cache_size, 0)
    {
    }
    ~WriteCachedStream() override { flush_cache(); }
    length_type read(void* output, offset_type offset, length_type length) override;
    void write(const void* input, offset_type offset, length_type length) override;
    length_type size() const override
    {
        return std::max(cached_length_ + cached_start_, delegate_->size());
    }
    void flush() override
    {
        flush_cache();
        delegate_->flush();
    }
    void resize(length_type size) override
    {
        flush_cache();
        delegate_->resize(size);
    }
    bool is_sparse() const noexcept override { return delegate_->is_sparse(); }
    length_type optimal_block_size() const noexcept override { return buffer_.size(); }

private:
    std::shared_ptr<StreamBase> delegate_;
    absl::FixedArray<unsigned char> buffer_;
    offset_type cached_start_ = 0;
    length_type cached_length_ = 0;

private:
    void flush_cache();
};
}    // namespace securefs
