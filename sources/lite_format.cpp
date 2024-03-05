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

    namespace
    {
        class LegacyNameTranslator : public NameTranslator
        {
        public:
            INJECT(LegacyNameTranslator(ANNOTATED(tNameMasterKey, key_type) name_master_key))
                : name_master_key_(name_master_key)
            {
            }

        private:
            key_type name_master_key_;
            ThreadLocal name_aes_siv_;
        };
    }    // namespace

    void FuseHighLevelOps::initialize(fuse_conn_info* info)
    {
        (void)info;
#ifdef FSP_FUSE_CAP_READDIR_PLUS
        info->want |= (info->capable & FSP_FUSE_CAP_READDIR_PLUS);
#endif
    }

    int FuseHighLevelOps::vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx)
    {
        root_->statfs(buf);
        buf->f_namemax = name_trans_.max_virtual_path_component_size(buf->f_namemax);
        return 0;
    }

}    // namespace lite_format

}    // namespace securefs
