#pragma once

#include "streams.h"

namespace securefs
{
class LiteCorruptedStreamException : public ExceptionBase
{
public:
    std::string message() const override;
    const char* type_name() const noexcept override;
};

class LiteAESGCMCryptStream : public BlockBasedStream
{
private:
    std::shared_ptr<StreamBase> m_stream;
    std::unique_ptr<byte[]> m_buffer;
    key_type m_session_key;
    unsigned m_iv_size;
    bool m_check;

private:
    unsigned get_block_size() const { return m_block_size; }

    unsigned get_iv_size() const { return m_iv_size; }

    unsigned get_mac_size() const { return 16; }

    unsigned get_header_size() const { return key_type{}.size(); }

    unsigned get_underlying_block_size() const
    {
        return get_block_size() + get_iv_size() + get_mac_size();
    }

protected:
    length_type read_block(offset_type block_number, void* output) override;

    void write_block(offset_type block_number, const void* input, length_type size) override;

    void adjust_logical_size(length_type length) override;

public:
    explicit LiteAESGCMCryptStream(std::shared_ptr<StreamBase> stream,
                                   const key_type& master_key,
                                   unsigned block_size = 4096,
                                   unsigned iv_size = 12,
                                   bool check = true);
    ~LiteAESGCMCryptStream();

    virtual length_type size() const override;

    virtual void flush() override;

    virtual bool is_sparse() const noexcept override;
};
}
