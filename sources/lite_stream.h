#pragma once

#include "mystring.h"
#include "streams.h"

#include <absl/container/inlined_vector.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rng.h>
#include <cryptopp/secblock.h>

namespace securefs::lite
{
class CorruptedStreamException : public ExceptionBase
{
public:
    std::string message() const override;
};

unsigned default_compute_padding(unsigned max_padding,
                                 CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption& padding_aes,
                                 const byte* id,
                                 size_t id_size);

class AESGCMCryptStream : public BlockBasedStream
{
private:
    CryptoPP::GCM<CryptoPP::AES>::Encryption m_encryptor;
    CryptoPP::GCM<CryptoPP::AES>::Decryption m_decryptor;
    std::shared_ptr<StreamBase> m_stream;
    absl::InlinedVector<byte, 32> m_auxiliary;
    unsigned m_iv_size, m_padding_size;
    bool m_check;

public:
    length_type get_block_size() const noexcept { return m_block_size; }

    length_type get_iv_size() const noexcept { return m_iv_size; }

    static constexpr unsigned get_mac_size() noexcept { return 16; }

    static constexpr length_type get_id_size() noexcept { return 16; }

    length_type get_header_size() const noexcept { return get_id_size() + get_padding_size(); }

    length_type get_underlying_block_size() const noexcept
    {
        return get_block_size() + get_iv_size() + get_mac_size();
    }

    unsigned get_padding_size() const noexcept { return m_padding_size; }

    struct ParamCalculator : public Object
    {
        virtual void compute_session_key(const std::array<unsigned char, 16>& id,
                                         std::array<unsigned char, 16>& outkey)
            = 0;
        virtual unsigned compute_padding(const std::array<unsigned char, 16>& id) = 0;
    };

protected:
    length_type
    read_multi_blocks(offset_type start_block, offset_type end_block, void* output) override;

    void write_multi_blocks(offset_type start_block,
                            offset_type end_block,
                            offset_type end_residue,
                            const void* input) override;

    void adjust_logical_size(length_type length) override;

public:
    explicit AESGCMCryptStream(std::shared_ptr<StreamBase> stream,
                               const key_type& master_key,
                               unsigned block_size = 4096,
                               unsigned iv_size = 12,
                               bool check = true,
                               unsigned max_padding_size = 0,
                               CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption* padding_aes
                               = nullptr);
    explicit AESGCMCryptStream(std::shared_ptr<StreamBase> stream,
                               ParamCalculator& calc,
                               unsigned block_size = 4096,
                               unsigned iv_size = 12,
                               bool check = true);

    ~AESGCMCryptStream();

    virtual length_type size() const override;

    virtual void flush() override;

    virtual bool is_sparse() const noexcept override;

    // Calculates the size of `AESGCMCryptStream` based on its underlying stream size. This only
    // works when padding is not enabled.
    static length_type calculate_real_size(length_type underlying_size,
                                           length_type block_size,
                                           length_type iv_size) noexcept;
};
}    // namespace securefs::lite
