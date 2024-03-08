#include "lite_format.h"
#include "crypto.h"
#include "exceptions.h"
#include "lite_long_name_lookup_table.h"
#include "lock_guard.h"
#include "logger.h"
#include "myutils.h"
#include "platform.h"

#include <absl/base/thread_annotations.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <absl/utility/utility.h>
#include <any>
#include <cstddef>
#include <fruit/fruit.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace securefs::lite_format
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
    auto* enc = std::any_cast<StreamOpener::AES_ECB>(&any);
    if (enc)
    {
        return *enc;
    }
    any.emplace<StreamOpener::AES_ECB>(content_master_key_.data(), content_master_key_.size());
    return *std::any_cast<StreamOpener::AES_ECB>(&any);
}

StreamOpener::AES_ECB& StreamOpener::get_thread_local_padding_master_enc()
{
    auto&& any = content_ecb.get();
    auto* enc = std::any_cast<StreamOpener::AES_ECB>(&any);
    if (enc)
    {
        return *enc;
    }
    any.emplace<StreamOpener::AES_ECB>(padding_master_key_.data(), padding_master_key_.size());
    return *std::any_cast<StreamOpener::AES_ECB>(&any);
}

void StreamOpener::validate()
{
    warn_if_key_not_random(content_master_key_, __FILE__, __LINE__);
    if (max_padding_size_ > 0)
    {
        warn_if_key_not_random(padding_master_key_, __FILE__, __LINE__);
    }
}

namespace
{
    class InvalidFilenameException : public VerificationException
    {
    private:
        std::string m_filename;

    public:
        explicit InvalidFilenameException(std::string filename) : m_filename(std::move(filename)) {}

        std::string message() const override
        {
            return absl::StrFormat("Invalid filename \"%s\"", m_filename);
        }
        int error_number() const noexcept override { return EINVAL; }
    };

    class LegacyNameTranslator : public NameTranslator
    {
    public:
        INJECT(LegacyNameTranslator(ANNOTATED(tNameMasterKey, const key_type&) name_master_key))
            : name_master_key_(name_master_key)
        {
        }

        std::string encrypt_full_path(std::string_view path,
                                      std::string* out_encrypted_last_component) override
        {
            if (path.empty())
            {
                return {};
            }
            else if (path.size() == 1 && path[0] == '/')
            {
                return ".";
            }
            auto str = legacy_encrypt_path(get_siv(), path);
            if (!str.empty() && str.front() == '/')
            {
                str.erase(str.begin());
                return str;
            }
            return str;
        }

        std::variant<InvalidNameTag, LongNameTag, std::string>
        decrypt_path_component(std::string_view path) override
        {
            std::string decoded_bytes;
            decoded_bytes.reserve(path.size());
            base32_decode(path.data(), path.size(), decoded_bytes);
            if (decoded_bytes.size() <= AES_SIV::IV_SIZE)
            {
                WARN_LOG("Skipping too small encrypted filename %s", path);
                return InvalidNameTag{};
            }
            std::string result(decoded_bytes.size() - AES_SIV::IV_SIZE, '\0');
            bool success = get_siv().decrypt_and_verify(&decoded_bytes[AES_SIV::IV_SIZE],
                                                        result.size(),
                                                        nullptr,
                                                        0,
                                                        result.data(),
                                                        decoded_bytes.data());
            if (success)
            {
                return result;
            }
            return InvalidNameTag();
        }

        std::string encrypt_path_for_symlink(std::string_view path) override
        {
            if (path.empty())
            {
                return {};
            }
            else if (path.size() == 1 && path[0] == '/')
            {
                return ".";
            }
            return legacy_encrypt_path(get_siv(), path);
        }
        std::string decrypt_path_from_symlink(std::string_view path) override
        {
            if (path.empty())
            {
                return {};
            }
            else if (path == ".")
            {
                return "/";
            }
            return legacy_decrypt_path(get_siv(), path);
        }

        unsigned max_virtual_path_component_size(unsigned physical_path_component_size) override
        {
            if (physical_path_component_size <= AES_SIV::IV_SIZE * 8 / 5)
            {
                return 0;
            }
            return physical_path_component_size * 5 / 8 - AES_SIV::IV_SIZE;
        }

    private:
        AES_SIV& get_siv()
        {
            auto&& any = name_aes_siv_.get();
            if (auto p = std::any_cast<std::shared_ptr<AES_SIV>>(&any))
            {
                return **p;
            }
            any.emplace<std::shared_ptr<AES_SIV>>(
                std::make_shared<AES_SIV>(name_master_key_.data(), name_master_key_.size()));
            return **std::any_cast<std::shared_ptr<AES_SIV>>(&any);
        }

        static std::string legacy_encrypt_path(AES_SIV& encryptor, std::string_view path)
        {
            byte buffer[2032];
            std::string result;
            result.reserve((path.size() * 8 + 4) / 5);
            size_t last_nonseparator_index = 0;
            std::string encoded_part;

            for (size_t i = 0; i <= path.size(); ++i)
            {
                if (i >= path.size() || path[i] == '/')
                {
                    if (i > last_nonseparator_index)
                    {
                        const char* slice = path.data() + last_nonseparator_index;
                        size_t slice_size = i - last_nonseparator_index;
                        if (slice_size > 2000)
                            throwVFSException(ENAMETOOLONG);
                        encryptor.encrypt_and_authenticate(
                            slice, slice_size, nullptr, 0, buffer + AES_SIV::IV_SIZE, buffer);
                        base32_encode(buffer, slice_size + AES_SIV::IV_SIZE, encoded_part);
                        result.append(encoded_part);
                    }
                    if (i < path.size())
                        result.push_back('/');
                    last_nonseparator_index = i + 1;
                }
            }
            return result;
        }

        static std::string legacy_decrypt_path(AES_SIV& decryptor, std::string_view path)
        {
            byte string_buffer[2032];
            std::string result, decoded_part;
            result.reserve(path.size() * 5 / 8 + 10);
            size_t last_nonseparator_index = 0;

            for (size_t i = 0; i <= path.size(); ++i)
            {
                if (i >= path.size() || path[i] == '/')
                {
                    if (i > last_nonseparator_index)
                    {
                        const char* slice = path.data() + last_nonseparator_index;
                        size_t slice_size = i - last_nonseparator_index;

                        base32_decode(slice, slice_size, decoded_part);
                        if (decoded_part.size() >= sizeof(string_buffer))
                            throwVFSException(ENAMETOOLONG);

                        bool success
                            = decryptor.decrypt_and_verify(&decoded_part[AES_SIV::IV_SIZE],
                                                           decoded_part.size() - AES_SIV::IV_SIZE,
                                                           nullptr,
                                                           0,
                                                           string_buffer,
                                                           &decoded_part[0]);
                        if (!success)
                            throw InvalidFilenameException(std::string(path));
                        result.append((const char*)string_buffer,
                                      decoded_part.size() - AES_SIV::IV_SIZE);
                    }
                    if (i < path.size())
                        result.push_back('/');
                    last_nonseparator_index = i + 1;
                }
            }
            return result;
        }

    private:
        key_type name_master_key_;
        ThreadLocal name_aes_siv_;
    };

    class NoOpNameTranslator : public NameTranslator
    {
    public:
        INJECT(NoOpNameTranslator()) {}
        bool is_no_op() const noexcept override { return true; }
        std::string encrypt_full_path(std::string_view path,
                                      std::string* out_encrypted_last_component) override
        {
            return {path.data(), path.size()};
        }

        absl::variant<InvalidNameTag, LongNameTag, std::string>
        decrypt_path_component(std::string_view path) override
        {
            return std::string{path.data(), path.size()};
        }

        std::string encrypt_path_for_symlink(std::string_view path) override
        {
            return {path.data(), path.size()};
        }
        std::string decrypt_path_from_symlink(std::string_view path) override
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
        DirectoryImpl(std::string dir_abs_path,
                      NameTranslator& name_trans,
                      StreamOpener& opener,
                      bool readdir_plus)
            : dir_abs_path_(std::move(dir_abs_path))
            , name_trans_(name_trans)
            , opener_(opener)
            , readdir_plus_(readdir_plus)
        {
            if (readdir_plus && !opener_.can_compute_virtual_size())
            {
                throw_runtime_error("Readdir plus should only be used without padding");
            }
            under_traverser_ = OSService::get_default().create_traverser(dir_abs_path_);
        }

        void fstat(fuse_stat* stat) override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
        {
            OSService().get_default().stat(dir_abs_path_, stat);
        }

        bool next(std::string* name, fuse_stat* stbuf) override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
        {
            std::string under_name;

            while (true)
            {
                if (!under_traverser_->next(&under_name, stbuf))
                    return false;
                if (!name)
                    return true;

                if (under_name.empty())
                    continue;
                if (under_name == "." || under_name == "..")
                {
                    if (name)
                        name->swap(under_name);
                    return true;
                }
                if (stbuf && readdir_plus_ && (stbuf->st_mode & S_IFMT) == S_IFREG)
                {
                    stbuf->st_size = opener_.compute_virtual_size(stbuf->st_size);
                }
                if (name_trans_.is_no_op())
                {
                    // Plain text name mode
                    name->swap(under_name);
                    return true;
                }
                if (under_name[0] == '.')
                    continue;
                try
                {
                    std::visit(Overload{[&](std::string&& decoded) { decoded.swap(*name); },
                                        [](const InvalidNameTag&) {},
                                        [&](const LongNameTag&) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
                                        {
                                            auto&& table = lazy_get_table();
                                            std::string encrypted_name;
                                            {
                                                LockGuard<LongNameLookupTable> lg(table);
                                                encrypted_name = table.lookup(under_name);
                                            }
                                            auto decoded = name_trans_.decrypt_path_component(
                                                encrypted_name);
                                            std::get<std::string>(decoded).swap(*name);
                                        }},
                               name_trans_.decrypt_path_component(under_name));
                }
                catch (const std::exception& e)
                {
                    WARN_LOG("Skipping filename %s/%s due to exception in decoding: %s",
                             dir_abs_path_,
                             under_name,
                             e.what());
                    continue;
                }
                return true;
            }
        }
        void rewind() override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) { under_traverser_->rewind(); }

    private:
        LongNameLookupTable& lazy_get_table() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
        {
            if (long_table_.has_value())
            {
                return *long_table_;
            }
            long_table_.emplace(
                OSService::concat_and_norm_narrowed(dir_abs_path_, LONG_NAME_DATABASE_FILE_NAME),
                true);
            return *long_table_;
        }

    private:
        std::optional<LongNameLookupTable> long_table_ ABSL_GUARDED_BY(*this);
        std::string dir_abs_path_;
        std::unique_ptr<DirectoryTraverser> under_traverser_ ABSL_GUARDED_BY(*this);
        NameTranslator& name_trans_;
        StreamOpener& opener_;
        bool readdir_plus_;
    };

    Base* get_base(fuse_file_info* info)
    {
        return reinterpret_cast<Base*>(static_cast<uintptr_t>(info->fh));
    }

    File* get_file_checked(fuse_file_info* info)
    {
        auto fp = get_base(info)->as_file();
        if (!fp)
        {
            throwVFSException(EISDIR);
        }
        return fp;
    }

    Directory* get_dir_checked(fuse_file_info* info)
    {
        auto fp = get_base(info)->as_dir();
        if (!fp)
        {
            throwVFSException(ENOTDIR);
        }
        return fp;
    }
}    // namespace

void FuseHighLevelOps::initialize(fuse_conn_info* info)
{
    (void)info;
#ifdef FSP_FUSE_CAP_READDIR_PLUS
    if (opener_.can_compute_virtual_size() && (info->capable & FSP_FUSE_CAP_READDIR_PLUS))
    {
        info->want |= FSP_FUSE_CAP_READDIR_PLUS;
        read_dir_plus_ = true;
    }
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

        if (!name_trans_.is_no_op())
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
                    auto virtual_file = opener_.open(root_.open_file_stream(enc_path, O_RDONLY, 0));
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
    auto fp = get_base(info);
    LockGuard<Base> lg(*fp);
    fp->fstat(st);
    return 0;
}
int FuseHighLevelOps::vopendir(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    auto dir = std::make_unique<DirectoryImpl>(
        root_.norm_path_narrowed(name_trans_.encrypt_full_path(path, nullptr)),
        name_trans_,
        opener_,
        read_dir_plus_);
    info->fh = reinterpret_cast<uintptr_t>(dir.release());
    return 0;
}
int FuseHighLevelOps::vreleasedir(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    delete get_base(info);
    return 0;
}
int FuseHighLevelOps::vreaddir(const char* path,
                               void* buf,
                               fuse_fill_dir_t filler,
                               fuse_off_t off,
                               fuse_file_info* info,
                               const fuse_context* ctx)
{
    auto dir = get_dir_checked(info);
    LockGuard<Directory> lg(*dir);

    std::string name;
    fuse_stat st{};
    dir->rewind();

    while (dir->next(&name, &st))
    {
        int rc = filler(buf, name.c_str(), &st, 0);
        if (rc != 0)
        {
            return -std::abs(rc);
        }
    }

    return 0;
}
int FuseHighLevelOps::vcreate(const char* path,
                              fuse_mode_t mode,
                              fuse_file_info* info,
                              const fuse_context* ctx)
{
    info->fh = reinterpret_cast<uintptr_t>(open(path, O_CREAT | O_EXCL | O_RDWR, mode).release());
    return 0;
}
int FuseHighLevelOps::vopen(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    info->fh = reinterpret_cast<uintptr_t>(open(path, info->flags, 0).release());
    return 0;
}
int FuseHighLevelOps::vrelease(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    delete get_base(info);
    return 0;
}
int FuseHighLevelOps::vread(const char* path,
                            char* buf,
                            size_t size,
                            fuse_off_t offset,
                            fuse_file_info* info,
                            const fuse_context* ctx)
{
    auto fp = get_file_checked(info);
    LockGuard<File> lg(*fp);
    return static_cast<int>(fp->read(buf, offset, size));
}
int FuseHighLevelOps::vwrite(const char* path,
                             const char* buf,
                             size_t size,
                             fuse_off_t offset,
                             fuse_file_info* info,
                             const fuse_context* ctx)
{
    auto fp = get_file_checked(info);
    LockGuard<File> lg(*fp);
    fp->write(buf, offset, size);
    return static_cast<int>(size);
}
int FuseHighLevelOps::vflush(const char* path, fuse_file_info* info, const fuse_context* ctx)
{
    auto fp = get_file_checked(info);
    LockGuard<File> lg(*fp);
    fp->flush();
    return 0;
}
int FuseHighLevelOps::vftruncate(const char* path,
                                 fuse_off_t len,
                                 fuse_file_info* info,
                                 const fuse_context* ctx)
{
    auto fp = get_file_checked(info);
    LockGuard<File> lg(*fp);
    fp->resize(len);
    return 0;
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
int FuseHighLevelOps::vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx)
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
int FuseHighLevelOps::vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx)
{
    return -ENOSYS;
}
int FuseHighLevelOps::vlistxattr(const char* path, char* list, size_t size, const fuse_context* ctx)
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
std::unique_ptr<File> FuseHighLevelOps::open(std::string_view path, int flags, unsigned mode)
{
    if (flags & O_APPEND)
    {
        flags &= ~((unsigned)O_APPEND);
        // Clear append flags. Workaround for FUSE bug.
        // See https://github.com/netheril96/securefs/issues/58.
    }

    // Files cannot be opened write-only because the header must be read in order to derive the
    // session key
    if ((flags & O_ACCMODE) == O_WRONLY)
    {
        flags = (flags & ~O_ACCMODE) | O_RDWR;
    }
    if ((flags & O_CREAT))
    {
        mode |= S_IRUSR;
    }
    std::string encrypted_last_component, enc_path;
    enc_path = name_trans_.encrypt_full_path(
        path, (flags & O_CREAT) ? &encrypted_last_component : nullptr);
    std::unique_ptr<File> fp;
    if (encrypted_last_component.empty())
    {
        fp = std::make_unique<File>(root_.open_file_stream(enc_path, flags, mode), opener_);
    }
    else
    {
        auto db_path = root_.norm_path_narrowed(absl::StrCat(
            name_trans_.remove_last_component(enc_path), LONG_NAME_DATABASE_FILE_NAME));
        LongNameLookupTable table(db_path, false);
        // Open a transaction so that we will rollback properly if opening the file stream later
        // fails.
        LockGuard<LongNameLookupTable> table_lg(table);
        table.insert_or_update(name_trans_.get_last_component(enc_path), encrypted_last_component);
        fp = std::make_unique<File>(root_.open_file_stream(enc_path, flags, mode), opener_);
    }

    if (flags & O_TRUNC)
    {
        LockGuard<File> lock_guard(*fp, true);
        fp->resize(0);
    }
    return fp;
}

fruit::Component<fruit::Required<fruit::Annotated<tNameMasterKey, key_type>>, NameTranslator>
get_name_translator_component(std::shared_ptr<NameNormalizationFlags> flags)
{
    // TODO: replace them with real name translators.
    return fruit::createComponent().bind<NameTranslator, NoOpNameTranslator>();
}

std::string_view NameTranslator::get_last_component(std::string_view path)
{
    return path.substr(path.rfind('/') + 1);
}

std::string_view NameTranslator::remove_last_component(std::string_view path)
{
    return path.substr(0, path.rfind('/') + 1);
}
}    // namespace securefs::lite_format
