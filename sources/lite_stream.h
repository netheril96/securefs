#pragma once

#include "streams.h"

namespace securefs
{
namespace lite
{
    class CorruptedStreamException : public ExceptionBase
    {
    public:
        std::string message() const override;

        const char* type_name() const noexcept override;
    };

    class AESGCMCryptStream : public BlockBasedStream
    {
    private:
        std::shared_ptr<StreamBase> m_stream;
        std::unique_ptr<byte[]> m_buffer;
        key_type m_session_key;
        unsigned m_iv_size;
        bool m_check;

    private:
        length_type get_block_size() const noexcept { return m_block_size; }

        length_type get_iv_size() const noexcept { return m_iv_size; }

        static unsigned get_mac_size() noexcept { return 16; }

        static length_type get_header_size() noexcept { return key_type{}.size(); }

        length_type get_underlying_block_size() const noexcept
        {
            return get_block_size() + get_iv_size() + get_mac_size();
        }

    protected:
        length_type read_block(offset_type block_number, void* output) override;

        void write_block(offset_type block_number, const void* input, length_type size) override;

        void adjust_logical_size(length_type length) override;

    public:
        explicit AESGCMCryptStream(std::shared_ptr<StreamBase> stream,
                                   const key_type& master_key,
                                   unsigned block_size = 4096,
                                   unsigned iv_size = 12,
                                   bool check = true);

        ~AESGCMCryptStream();

        virtual length_type size() const override;

        virtual void flush() override;

        virtual bool is_sparse() const noexcept override;

        static length_type calculate_real_size(length_type underlying_size,
                                               length_type block_size,
                                               length_type iv_size) noexcept;
    };
}
}
