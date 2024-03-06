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

        class NoOpNameTranslator : public NameTranslator
        {
        public:
            INJECT(NoOpNameTranslator()) {}
            virtual std::string
            encrypt_full_path(absl::string_view path,
                              std::string* out_encrypted_last_component) override
            {
                return {path.data(), path.size()};
            }

            virtual std::string decrypt_path_component(absl::string_view path) override
            {
                return {path.data(), path.size()};
            }

            virtual std::string encrypt_path_for_symlink(absl::string_view path) override
            {
                return {path.data(), path.size()};
            }
            virtual std::string decrypt_path_from_symlink(absl::string_view path) override
            {
                return {path.data(), path.size()};
            }

            virtual unsigned
            max_virtual_path_component_size(unsigned physical_path_component_size) override
            {
                return physical_path_component_size;
            }
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
        root_.statfs(buf);
        buf->f_namemax = name_trans_.max_virtual_path_component_size(buf->f_namemax);
        return 0;
    }
    int FuseHighLevelOps::vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vfgetattr(const char* path,
                                    fuse_stat* st,
                                    fuse_file_info* info,
                                    const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vopendir(const char* path, fuse_file_info* info, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int
    FuseHighLevelOps::vreleasedir(const char* path, fuse_file_info* info, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vreaddir(const char* path,
                                   void* buf,
                                   fuse_fill_dir_t filler,
                                   fuse_off_t off,
                                   fuse_file_info* info,
                                   const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vcreate(const char* path,
                                  fuse_mode_t mode,
                                  fuse_file_info* info,
                                  const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vopen(const char* path, fuse_file_info* info, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vrelease(const char* path, fuse_file_info* info, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vread(const char* path,
                                char* buf,
                                size_t size,
                                fuse_off_t offset,
                                fuse_file_info* info,
                                const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vwrite(const char* path,
                                 const char* buf,
                                 size_t size,
                                 fuse_off_t offset,
                                 fuse_file_info* info,
                                 const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vflush(const char* path, fuse_file_info* info, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vftruncate(const char* path,
                                     fuse_off_t len,
                                     fuse_file_info* info,
                                     const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vunlink(const char* path, const fuse_context* ctx) { return -ENOSYS; };
    int FuseHighLevelOps::vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vrmdir(const char* path, const fuse_context* ctx) { return -ENOSYS; };
    int FuseHighLevelOps::vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vchown(const char* path,
                                 fuse_uid_t uid,
                                 fuse_gid_t gid,
                                 const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vsymlink(const char* to, const char* from, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vlink(const char* src, const char* dest, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int
    FuseHighLevelOps::vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vrename(const char* from, const char* to, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vfsync(const char* path,
                                 int datasync,
                                 fuse_file_info* info,
                                 const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int
    FuseHighLevelOps::vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int
    FuseHighLevelOps::vlistxattr(const char* path, char* list, size_t size, const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vgetxattr(const char* path,
                                    const char* name,
                                    char* value,
                                    size_t size,
                                    uint32_t position,
                                    const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vsetxattr(const char* path,
                                    const char* name,
                                    const char* value,
                                    size_t size,
                                    int flags,
                                    uint32_t position,
                                    const fuse_context* ctx)
    {
        return -ENOSYS;
    }
    int FuseHighLevelOps::vremovexattr(const char* path, const char* name, const fuse_context* ctx)
    {
        return -ENOSYS;
    }

    fruit::Component<fruit::Required<fruit::Annotated<tNameMasterKey, key_type>>, NameTranslator>
    get_name_translator_component(NameNormalizationFlags args)
    {
        // TODO: replace them with real name translators.
        return fruit::createComponent().bind<NameTranslator, NoOpNameTranslator>();
    }
}    // namespace lite_format

}    // namespace securefs
