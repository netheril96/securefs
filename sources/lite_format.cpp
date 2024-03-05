#include "lite_format.h"

namespace securefs
{

namespace lite_format
{
    std::unique_ptr<securefs::lite::AESGCMCryptStream>
    StreamOpener::open(std::shared_ptr<StreamBase> base)
    {
        return std::make_unique<securefs::lite::AESGCMCryptStream>(
            base, *this, block_size_, iv_size_, !skip_verification_);
    }

    void StreamOpener::compute_session_key(const std::array<unsigned char, 16>& id,
                                           std::array<unsigned char, 16>& outkey)
    {
        get_thread_local_content_master_enc().ProcessData(outkey.data(), id.data(), id.size());
    }

    unsigned StreamOpener::compute_padding(const std::array<unsigned char, 16>& id)
    {
        if (max_padding_size_ <= 0)
        {
            return 0;
        }
        return lite::default_compute_padding(
            max_padding_size_, get_thread_local_padding_master_enc(), id.data(), id.size());
    }

    StreamOpener::AES_ECB& StreamOpener::get_thread_local_content_master_enc()
    {
        auto&& any = content_ecb.get();
        auto* enc = absl::any_cast<StreamOpener::AES_ECB*>(any);
        if (enc)
        {
            return *enc;
        }
        any.emplace<StreamOpener::AES_ECB>(content_master_key_.data(), content_master_key_.size());
        return *absl::any_cast<StreamOpener::AES_ECB*>(any);
    }

    StreamOpener::AES_ECB& StreamOpener::get_thread_local_padding_master_enc()
    {
        auto&& any = content_ecb.get();
        auto* enc = absl::any_cast<StreamOpener::AES_ECB*>(any);
        if (enc)
        {
            return *enc;
        }
        any.emplace<StreamOpener::AES_ECB>(padding_master_key_.data(), padding_master_key_.size());
        return *absl::any_cast<StreamOpener::AES_ECB*>(any);
    }

}    // namespace lite_format

}    // namespace securefs
