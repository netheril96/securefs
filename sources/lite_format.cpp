#include "lite_format.h"
#include "logger.h"
#include "platform.h"
#include <absl/strings/string_view.h>
#include <cerrno>
#include <memory>

namespace securefs
{
namespace lite_format
{
    std::unique_ptr<securefs::lite::AESGCMCryptStream>
    StreamOpener::open(std::shared_ptr<StreamBase> base)
    {
        return std::make_unique<securefs::lite::AESGCMCryptStream>(
            std::move(base), *this, block_size_, iv_size_, !skip_verification_);
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
            INJECT(LegacyNameTranslator(ANNOTATED(tNameMasterKey, const key_type&) name_master_key))
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
            std::string encrypt_full_path(absl::string_view path,
                                          std::string* out_encrypted_last_component) override
            {
                return {path.data(), path.size()};
            }

            std::string decrypt_path_component(absl::string_view path) override
            {
                return {path.data(), path.size()};
            }

            std::string encrypt_path_for_symlink(absl::string_view path) override
            {
                return {path.data(), path.size()};
            }
            std::string decrypt_path_from_symlink(absl::string_view path) override
            {
                return {path.data(), path.size()};
            }

            unsigned max_virtual_path_component_size(unsigned physical_path_component_size) override
            {
                return physical_path_component_size;
            }
        };

        class DirectoryImpl : public Directory
        {
        public:
            INJECT(DirectoryImpl(std::string dir_abs_path,
                                 std::unique_ptr<DirectoryTraverser> underlying_traverser,
                                 StreamOpener& opener,
                                 NameTranslator& name_trans));
        };
    }    // namespace

    void FuseHighLevelOps::initialize(fuse_conn_info* info)
    {
        (void)info;
#ifdef FSP_FUSE_CAP_READDIR_PLUS
        info->want |= (info->capable & FSP_FUSE_CAP_READDIR_PLUS);
        read_dir_plus_ = true;
#endif
    }

    int FuseHighLevelOps::vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx)
    {
        root_.statfs(buf);
        buf->f_namemax = name_trans_.max_virtual_path_component_size(buf->f_namemax);
        return 0;
    }
    int FuseHighLevelOps::vgetattr(const char* path, fuse_stat* buf, const fuse_context* ctx)
    {
        auto enc_path = name_trans_.encrypt_full_path(path, nullptr);
        if (!root_.stat(enc_path, buf))
            return -ENOENT;
        if (buf->st_size <= 0)
            return 0;
        switch (buf->st_mode & S_IFMT)
        {
        case S_IFLNK:
        {
            // This is a workaround for Interix symbolic links on NTFS volumes
            // (https://github.com/netheril96/securefs/issues/43).

            // 'buf->st_size' is the expected link size, but on NTFS volumes the link starts with
            // 'IntxLNK\1' followed by the UTF-16 encoded target.
            std::string buffer(buf->st_size, '\0');
            ssize_t link_size = root_.readlink(enc_path, &buffer[0], buffer.size());
            if (link_size != buf->st_size && link_size != (buf->st_size - 8) / 2)
                throwVFSException(EIO);

            if (dynamic_cast<NoOpNameTranslator*>(&name_trans_) == nullptr)
            {
                // Resize to actual size
                buffer.resize(static_cast<size_t>(link_size));
                auto resolved = name_trans_.decrypt_path_from_symlink(buffer);
                buf->st_size = resolved.size();
            }
            else
            {
                buf->st_size = link_size;
            }
            break;
        }
        case S_IFDIR:
            break;
        case S_IFREG:
            if (buf->st_size > 0)
            {
                if (opener_.can_compute_virtual_size())
                {
                    buf->st_size = opener_.compute_virtual_size(buf->st_size);
                }
                else
                {
                    try
                    {
                        auto virtual_file
                            = opener_.open(root_.open_file_stream(enc_path, O_RDONLY, 0));
                        buf->st_size = virtual_file->size();
                    }
                    catch (const std::exception& e)
                    {
                        ERROR_LOG("Encountered exception %s when opening file %s for read: %s",
                                  get_type_name(e).get(),
                                  path,
                                  e.what());
                    }
                }
            }
            break;
        default:
            throwVFSException(ENOTSUP);
        }
        return 0;
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
