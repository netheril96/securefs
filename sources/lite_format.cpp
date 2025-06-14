#include "lite_format.h"
#include "apple_xattr_workaround.h"
#include "crypto.h"
#include "crypto_wrappers.h"
#include "exceptions.h"
#include "lite_long_name_lookup_table.h"
#include "lock_guard.h"
#include "logger.h"
#include "mystring.h"
#include "myutils.h"
#include "params.pb.h"
#include "platform.h"
#include "tags.h"
#include "xattr_name.h"

#include <absl/base/thread_annotations.h>
#include <absl/container/inlined_vector.h>
#include <absl/strings/match.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <absl/strings/str_join.h>
#include <absl/strings/str_split.h>
#include <absl/utility/utility.h>
#include <cryptopp/blake2.h>
#include <cryptopp/sha.h>
#include <cstdio>
#include <uni_algo/case.h>
#include <uni_algo/norm.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace securefs::lite_format
{
std::unique_ptr<securefs::lite::AESGCMCryptStream>
StreamOpener::open(std::shared_ptr<StreamBase> base)
{
    return std::make_unique<securefs::lite::AESGCMCryptStream>(
        std::move(base), *this, block_size_, iv_size_, verify_);
}

void StreamOpener::compute_session_key(const std::array<unsigned char, 16>& id,
                                       std::array<unsigned char, 16>& outkey)
{
    content_ecb.get().ProcessData(outkey.data(), id.data(), id.size());
}

unsigned StreamOpener::compute_padding(const std::array<unsigned char, 16>& id)
{
    if (max_padding_size_ <= 0)
    {
        return 0;
    }
    return lite::default_compute_padding(
        max_padding_size_, padding_ecb.get(), id.data(), id.size());
}

void StreamOpener::validate()
{
    warn_if_key_not_random(content_master_key_, __FILE__, __LINE__);
    if (max_padding_size_ > 0)
    {
        warn_if_key_not_random(padding_master_key_, __FILE__, __LINE__);
        if (padding_master_key_ == decltype(padding_master_key_)())
        {
            throw_runtime_error("Padding key is empty");
        }
    }
}

std::vector<byte> XattrCryptor::encrypt(const char* value, size_t size)
{
    std::vector<byte> result(infer_encrypted_size(size));
    securefs::libcrypto::generate_random(MutableRawBuffer(result.data(), iv_size_));
    crypt_.get().enc.EncryptAndAuthenticate(result.data() + iv_size_,
                                            result.data() + (result.size() - kMacSize),
                                            kMacSize,
                                            result.data(),
                                            static_cast<int>(iv_size_),
                                            nullptr,
                                            0,
                                            reinterpret_cast<const byte*>(value),
                                            size);
    return result;
}
void XattrCryptor::decrypt(const byte* input, size_t size, byte* output, size_t out_size)
{
    if (size < infer_encrypted_size(out_size))
    {
        throwInvalidArgumentException("Insufficent output buffer size");
    }
    bool success = crypt_.get().dec.DecryptAndVerify(output,
                                                     input + (size - kMacSize),
                                                     kMacSize,
                                                     input,
                                                     static_cast<int>(iv_size_),
                                                     nullptr,
                                                     0,
                                                     input + iv_size_,
                                                     size - iv_size_ - kMacSize);
    if (!success && verify_)
    {
        throw XattrVerificationException();
    }
}
size_t XattrCryptor::infer_decrypted_size(size_t encrypted_size)
{
    if (encrypted_size >= iv_size_ + kMacSize)
    {
        return encrypted_size - (iv_size_ + kMacSize);
    }
    return 0;
}
size_t XattrCryptor::infer_encrypted_size(size_t decrypted_size)
{
    return decrypted_size + iv_size_ + kMacSize;
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

    class AESSIVBasedNameTranslator : public NameTranslator
    {
    public:
        static constexpr size_t kSIVSize = AES_SIV::IV_SIZE;

        explicit AESSIVBasedNameTranslator(const key_type& name_master_key)
            : name_master_key_(name_master_key)
            , name_aes_siv_(
                  [this]() {
                      return std::make_unique<AES_SIV>(name_master_key_.data(),
                                                       name_master_key_.size());
                  })
        {
        }

    protected:
        AES_SIV& get_siv() { return name_aes_siv_.get(); }

    protected:
        key_type name_master_key_;
        ThreadLocal<AES_SIV> name_aes_siv_;
    };

    class LegacyNameTranslator : public AESSIVBasedNameTranslator
    {
    public:
        LegacyNameTranslator(const key_type& name_master_key)
            : AESSIVBasedNameTranslator(name_master_key)
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
            if (decoded_bytes.size() <= kSIVSize)
            {
                WARN_LOG("Skipping too small encrypted filename %s", path);
                return InvalidNameTag{};
            }
            std::string result(decoded_bytes.size() - kSIVSize, '\0');
            bool success = get_siv().decrypt_and_verify(&decoded_bytes[kSIVSize],
                                                        result.size(),
                                                        nullptr,
                                                        0,
                                                        result.data(),
                                                        decoded_bytes.data());
            if (success)
            {
                return result;
            }
            return InvalidNameTag{};
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
            if (physical_path_component_size <= kSIVSize * 8 / 5)
            {
                return 0;
            }
            return physical_path_component_size * 5 / 8 - kSIVSize;
        }

    private:
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
                            slice, slice_size, nullptr, 0, buffer + kSIVSize, buffer);
                        base32_encode(buffer, slice_size + kSIVSize, encoded_part);
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

                        bool success = decryptor.decrypt_and_verify(&decoded_part[kSIVSize],
                                                                    decoded_part.size() - kSIVSize,
                                                                    nullptr,
                                                                    0,
                                                                    string_buffer,
                                                                    &decoded_part[0]);
                        if (!success)
                            throw InvalidFilenameException(std::string(path));
                        result.append((const char*)string_buffer, decoded_part.size() - kSIVSize);
                    }
                    if (i < path.size())
                        result.push_back('/');
                    last_nonseparator_index = i + 1;
                }
            }
            return result;
        }
    };

    class NewStyleNameTranslator : public AESSIVBasedNameTranslator
    {
    private:
        std::string long_name_suffix_;
        unsigned threshold_;

    public:
        static constexpr size_t kHashSize = 32;
        static constexpr size_t kComponentSizeInSymlink = 60;

        static constexpr std::string_view kLegacyLongNameSuffix = "...";
        // Default to "..." for backward compatibility if not specified.
        NewStyleNameTranslator(const key_type& name_master_key,
                               unsigned long_name_threshold,
                               std::string long_name_suffix)
            : AESSIVBasedNameTranslator(name_master_key)
            , threshold_(long_name_threshold)
            , long_name_suffix_(std::move(long_name_suffix))
        {
            if (long_name_suffix_.empty())
            {
                long_name_suffix_ = kLegacyLongNameSuffix;
            }
        }

        std::string encrypt_full_path(std::string_view path,
                                      std::string* out_encrypted_last_component) override
        {
            absl::InlinedVector<std::string_view, 7> splits = absl::StrSplit(path, '/');
            std::string result;
            result.reserve(path.size() * 3);
            result.push_back('.');

            absl::InlinedVector<unsigned char, 256> aes_buffer;
            std::string part;
            part.reserve(260);

            auto&& siv = get_siv();

            for (std::string_view view : splits)
            {
                result.push_back('/');
                if (view.empty())
                {
                    continue;
                }
                if (view.size() <= threshold_)
                {
                    aes_buffer.resize(view.size() + kSIVSize);
                    siv.encrypt_and_authenticate(view.data(),
                                                 view.size(),
                                                 nullptr,
                                                 0,
                                                 aes_buffer.data() + kSIVSize,
                                                 aes_buffer.data());
                    base32_encode(aes_buffer.data(), aes_buffer.size(), part);
                    result.append(part);
                }
                else
                {
                    aes_buffer.resize(kHashSize + kSIVSize);
                    CryptoPP::BLAKE2b blake(reinterpret_cast<const byte*>(name_master_key_.data()),
                                            name_master_key_.size(),
                                            nullptr,
                                            0,
                                            nullptr,
                                            0,
                                            false,
                                            kHashSize);
                    blake.Update(reinterpret_cast<const byte*>(view.data()), view.size());
                    std::array<unsigned char, kHashSize> digest;
                    blake.TruncatedFinal(digest.data(), digest.size());
                    siv.encrypt_and_authenticate(digest.data(),
                                                 digest.size(),
                                                 nullptr,
                                                 0,
                                                 aes_buffer.data() + kSIVSize,
                                                 aes_buffer.data());
                    base32_encode(aes_buffer.data(), aes_buffer.size(), part);
                    result.append(part);
                    result.append(long_name_suffix_);
                }
            }
            if (out_encrypted_last_component != nullptr && !splits.empty()
                && splits.back().size() > threshold_)
            {
                auto view = splits.back();
                aes_buffer.resize(view.size() + kSIVSize);
                siv.encrypt_and_authenticate(view.data(),
                                             view.size(),
                                             nullptr,
                                             0,
                                             aes_buffer.data() + kSIVSize,
                                             aes_buffer.data());
                base32_encode(aes_buffer.data(), aes_buffer.size(), *out_encrypted_last_component);
            }
            return result;
        }

        std::variant<InvalidNameTag, LongNameTag, std::string>
        decrypt_path_component(std::string_view path) override
        {
            if (absl::EndsWith(path, long_name_suffix_))
            {
                return LongNameTag{};
            }
            std::string decoded_bytes;
            decoded_bytes.reserve(path.size());
            base32_decode(path.data(), path.size(), decoded_bytes);
            if (decoded_bytes.size() <= kSIVSize)
            {
                WARN_LOG("Skipping too small encrypted filename %s", path);
                return InvalidNameTag{};
            }
            std::string result(decoded_bytes.size() - kSIVSize, '\0');
            bool success = get_siv().decrypt_and_verify(&decoded_bytes[kSIVSize],
                                                        result.size(),
                                                        nullptr,
                                                        0,
                                                        result.data(),
                                                        decoded_bytes.data());
            if (success)
            {
                return result;
            }
            return InvalidNameTag{};
        }

        std::string encrypt_path_for_symlink(std::string_view path) override
        {
            if (path.empty())
            {
                return {};
            }
            std::vector<unsigned char> buffer(path.size() + kSIVSize);
            get_siv().encrypt_and_authenticate(
                path.data(), path.size(), nullptr, 0, buffer.data() + kSIVSize, buffer.data());
            std::string result, part;
            result.reserve(path.size() * 2);
            part.reserve(255);
            for (size_t i = 0; i < buffer.size(); i += kComponentSizeInSymlink)
            {
                base32_encode(
                    buffer.data() + i, std::min(kComponentSizeInSymlink, buffer.size() - i), part);
                result.push_back('/');
                result.append(part);
            }
            return result;
        }

        std::string decrypt_path_from_symlink(std::string_view path) override
        {
            if (path.empty())
            {
                return {};
            }
            std::string tmp, decoded;
            tmp.reserve(path.size());
            decoded.reserve(path.size());
            for (char c : path)
            {
                if (c != '/')
                {
                    tmp.push_back(c);
                }
            }
            base32_decode(tmp.data(), tmp.size(), decoded);
            if (decoded.size() <= kSIVSize)
            {
                return {};
            }
            tmp.resize(decoded.size() - kSIVSize);
            if (!get_siv().decrypt_and_verify(decoded.data() + kSIVSize,
                                              decoded.size() - kSIVSize,
                                              nullptr,
                                              0,
                                              tmp.data(),
                                              decoded.data()))
            {
                throw InvalidFilenameException(std::string(path));
            }
            return tmp;
        }

        unsigned max_virtual_path_component_size(unsigned physical_path_component_size) override
        {
            if (physical_path_component_size <= (threshold_ + kSIVSize) * 8 / 5)
            {
                return physical_path_component_size * 5 / 8 - kSIVSize;
            }
            return 65535;
        }
    };

    class NoOpNameTranslator : public NameTranslator
    {
    public:
        NoOpNameTranslator() = default;
        bool is_no_op() const noexcept override { return true; }
        std::string encrypt_full_path(std::string_view path,
                                      std::string* out_encrypted_last_component) override
        {
            if (absl::StartsWith(path, "/"))
            {
                return absl::StrCat(".", path);
            }
            return absl::StrCat("./", path);
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

    class PathNormalizingNameTranslator : public NameTranslator
    {
    public:
        PathNormalizingNameTranslator(std::shared_ptr<NameTranslator> delegate,
                                      bool case_fold,
                                      bool nfc)
            : delegate_(std::move(delegate)), case_fold_(case_fold), nfc_(nfc)
        {
        }

        std::string encrypt_full_path(std::string_view path,
                                      std::string* out_encrypted_last_component) override
        {
            try
            {
                std::string normed_string;
                std::string_view subject = path;
                if (nfc_)
                {
                    normed_string = una::norm::to_nfc_utf8(subject);
                    subject = normed_string;
                }
                if (case_fold_)
                {
                    normed_string = una::cases::to_casefold_utf8(subject);
                    subject = normed_string;
                }
                return delegate_->encrypt_full_path(normed_string, out_encrypted_last_component);
            }
            catch (const std::exception& e)
            {
                WARN_LOG("Failed to normalize path %s: %s", path, e.what());
                return delegate_->encrypt_full_path(path, out_encrypted_last_component);
            }
        }

        absl::variant<InvalidNameTag, LongNameTag, std::string>
        decrypt_path_component(std::string_view path) override
        {
            return delegate_->decrypt_path_component(path);
        }

        std::string encrypt_path_for_symlink(std::string_view path) override
        {
            return delegate_->encrypt_path_for_symlink(path);
        }
        std::string decrypt_path_from_symlink(std::string_view path) override
        {
            return delegate_->decrypt_path_from_symlink(path);
        }

        unsigned max_virtual_path_component_size(unsigned physical_path_component_size) override
        {
            return delegate_->max_virtual_path_component_size(physical_path_component_size);
        }

    private:
        std::shared_ptr<NameTranslator> delegate_;
        bool case_fold_;
        bool nfc_;
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
                OSService::concat_and_norm_narrowed(dir_abs_path_, kLongNameTableFileName), true);
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
    if (opener_->can_compute_virtual_size() && (info->capable & FSP_FUSE_CAP_READDIR_PLUS))
    {
        info->want |= FSP_FUSE_CAP_READDIR_PLUS;
        read_dir_plus_ = true;
    }
#endif
}

int FuseHighLevelOps::vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx)
{
    root_->statfs(buf);
    buf->f_namemax = name_trans_->max_virtual_path_component_size(buf->f_namemax);
    return 0;
}
int FuseHighLevelOps::vgetattr(const char* path, fuse_stat* buf, const fuse_context* ctx)
{
    auto enc_path = name_trans_->encrypt_full_path(path, nullptr);
    if (!root_->stat(enc_path, buf))
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
        ssize_t link_size = root_->readlink(enc_path, &buffer[0], buffer.size());
        if (link_size != buf->st_size && link_size != (buf->st_size - 8) / 2)
            throwVFSException(EIO);

        if (!name_trans_->is_no_op())
        {
            // Resize to actual size
            buffer.resize(static_cast<size_t>(link_size));
            auto resolved = name_trans_->decrypt_path_from_symlink(buffer);
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
            if (opener_->can_compute_virtual_size())
            {
                buf->st_size = opener_->compute_virtual_size(buf->st_size);
            }
            else
            {
                try
                {
                    auto physical_file = root_->open_file_stream(enc_path, O_RDONLY, 0);
                    physical_file->lock(true);
                    DEFER(physical_file->unlock());
                    auto virtual_file = opener_->open(physical_file);
                    buf->st_size = virtual_file->size();
                }
                catch (const std::exception& e)
                {
                    ERROR_LOG("Encountered exception %s when opening file %s for read: %s",
                              get_type_name(e).get(),
                              path,
                              e.what());
                    throw;
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
        root_->norm_path_narrowed(name_trans_->encrypt_full_path(path, nullptr)),
        *name_trans_,
        *opener_,
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
int FuseHighLevelOps::vunlink(const char* path, const fuse_context* ctx)
{
    process_possible_long_name(path,
                               LongNameComponentAction::kDelete,
                               [&](std::string&& enc_path) { root_->remove_file(enc_path); });
    return 0;
};
int FuseHighLevelOps::vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx)
{
    process_possible_long_name(path,
                               LongNameComponentAction::kCreate,
                               [&](std::string&& enc_path) { root_->mkdir(enc_path, mode); });
    return 0;
}
int FuseHighLevelOps::vrmdir(const char* path, const fuse_context* ctx)
{
    process_possible_long_name(path,
                               LongNameComponentAction::kDelete,
                               [&](std::string&& enc_path)
                               {
                                   root_->remove_file_nothrow(
                                       absl::StrCat(enc_path, "/", kLongNameTableFileName));
                                   root_->remove_directory(enc_path);
                               });
    return 0;
}
int FuseHighLevelOps::vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx)
{
    root_->chmod(name_trans_->encrypt_full_path(path, nullptr), mode);
    return 0;
}
int FuseHighLevelOps::vchown(const char* path,
                             fuse_uid_t uid,
                             fuse_gid_t gid,
                             const fuse_context* ctx)
{
    root_->chown(name_trans_->encrypt_full_path(path, nullptr), uid, gid);
    return 0;
}
int FuseHighLevelOps::vsymlink(const char* to, const char* from, const fuse_context* ctx)
{
    process_possible_long_name(
        from,
        LongNameComponentAction::kCreate,
        [&](std::string&& enc_path)
        { root_->symlink(name_trans_->encrypt_path_for_symlink(to), enc_path); });
    return 0;
}
int FuseHighLevelOps::vlink(const char* src, const char* dest, const fuse_context* ctx)
{
    process_possible_long_name(
        dest,
        LongNameComponentAction::kCreate,
        [&](std::string&& enc_path)
        { root_->link(name_trans_->encrypt_full_path(src, nullptr), enc_path); });
    return 0;
}
int FuseHighLevelOps::vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx)
{
    memset(buf, 0, size);
    if (size <= 1)
    {
        return 0;
    }

    auto max_size = size * 2 + 127;
    std::vector<char> buffer(max_size);
    root_->readlink(name_trans_->encrypt_full_path(path, nullptr), buffer.data(), max_size - 1);
    std::string resolved = name_trans_->decrypt_path_from_symlink(std::string_view(buffer.data()));
    size_t copy_size = std::min(resolved.size(), size - 1);
    memcpy(buf, resolved.data(), copy_size);
    buf[copy_size] = '\0';
    return 0;
}
int FuseHighLevelOps::vrename(const char* from, const char* to, const fuse_context* ctx)
{
    std::string encrypted_last_component_from, encrypted_last_component_to;
    auto enc_from = name_trans_->encrypt_full_path(from, &encrypted_last_component_from);
    auto enc_to = name_trans_->encrypt_full_path(to, &encrypted_last_component_to);

    if (encrypted_last_component_from.empty() && encrypted_last_component_to.empty())
    {
        // Neither are long name, so fast path.
        root_->rename(enc_from, enc_to);
        return 0;
    }

    DoubleLongNameLookupTable table(long_name_table_file_name(enc_from),
                                    long_name_table_file_name(enc_to));
    LockGuard<decltype(table)> lg(table);

    if (!encrypted_last_component_from.empty())
    {
        table.remove_mapping_from_from_db(name_trans_->get_last_component(enc_from));
    }
    if (!encrypted_last_component_to.empty())
    {
        table.update_mapping_to_to_db(name_trans_->get_last_component(enc_to),
                                      encrypted_last_component_to);
    }
    root_->rename(enc_from, enc_to);
    return 0;
}
int FuseHighLevelOps::vfsync(const char* path,
                             int datasync,
                             fuse_file_info* info,
                             const fuse_context* ctx)
{
    auto fp = get_file_checked(info);
    LockGuard<File> lg(*fp);
    fp->flush();
    fp->fsync();
    return 0;
}
int FuseHighLevelOps::vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx)
{
    auto fp = open(path, O_WRONLY, 0);
    LockGuard<File> lg(*fp);
    fp->resize(len);
    return 0;
}
int FuseHighLevelOps::vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx)
{
    root_->utimens(name_trans_->encrypt_full_path(path, nullptr), ts);
    return 0;
}
int FuseHighLevelOps::vlistxattr(const char* path, char* list, size_t size, const fuse_context* ctx)
{
    auto encrypted_path = name_trans_->encrypt_full_path(path, nullptr);
    if (xattr_name_cryptor_)
    {
        return generic_xattr::wrapped_listxattr(
            [&](char* buffer, size_t size)
            { return root_->listxattr(encrypted_path.c_str(), buffer, size); },
            *xattr_name_cryptor_,
            list,
            size);
    }

    int rc = root_->listxattr(name_trans_->encrypt_full_path(path, nullptr).c_str(), list, size);
    if (rc < 0)
    {
        return rc;
    }
    securefs::apple_xattr::transform_listxattr_result(list, size);
    return rc;
}
int FuseHighLevelOps::vgetxattr(const char* path,
                                const char* name,
                                char* value,
                                size_t size,
                                uint32_t position,
                                const fuse_context* ctx)
{
    if (position != 0)
    {
        return -EINVAL;
    }
    if (is_apple())
    {
        if (int rc = securefs::apple_xattr::precheck_getxattr(&name); rc <= 0)
        {
            return rc;
        }
    }
    std::string wrapped_name = xattr_name_cryptor_
        ? generic_xattr::encrypt_xattr_name(*xattr_name_cryptor_, name)
        : name;

    if (!value)
    {
        ssize_t rc = root_->getxattr(name_trans_->encrypt_full_path(path, nullptr).c_str(),
                                     wrapped_name.c_str(),
                                     nullptr,
                                     0);
        if (rc < 0)
        {
            return rc;
        }
        return static_cast<int>(xattr_->infer_decrypted_size(rc));
    }
    std::vector<byte> underlying_data(xattr_->infer_encrypted_size(size));
    auto rc = root_->getxattr(name_trans_->encrypt_full_path(path, nullptr).c_str(),
                              wrapped_name.c_str(),
                              underlying_data.data(),
                              underlying_data.size());
    if (rc < 0)
    {
        return static_cast<int>(rc);
    }
    xattr_->decrypt(
        underlying_data.data(), underlying_data.size(), reinterpret_cast<byte*>(value), size);
    return static_cast<int>(xattr_->infer_decrypted_size(rc));
}
int FuseHighLevelOps::vsetxattr(const char* path,
                                const char* name,
                                const char* value,
                                size_t size,
                                int flags,
                                uint32_t position,
                                const fuse_context* ctx)
{
    if (position != 0)
    {
        return -EINVAL;
    }
    if (is_apple())
    {
        if (int rc = securefs::apple_xattr::precheck_setxattr(&name, &flags); rc <= 0)
        {
            return rc;
        }
    }
    if (!value || size == 0)
    {
        return 0;
    }

    std::string wrapped_name = xattr_name_cryptor_
        ? generic_xattr::encrypt_xattr_name(*xattr_name_cryptor_, name)
        : name;

    auto data = xattr_->encrypt(value, size);
    return root_->setxattr(name_trans_->encrypt_full_path(path, nullptr).c_str(),
                           wrapped_name.c_str(),
                           data.data(),
                           data.size(),
                           flags);
}
int FuseHighLevelOps::vremovexattr(const char* path, const char* name, const fuse_context* ctx)
{
    if (is_apple())
    {
        int rc = securefs::apple_xattr::precheck_removexattr(&name);
        if (rc <= 0)
        {
            return rc;
        }
    }

    std::string wrapped_name = xattr_name_cryptor_
        ? generic_xattr::encrypt_xattr_name(*xattr_name_cryptor_, name)
        : name;

    return root_->removexattr(name_trans_->encrypt_full_path(path, nullptr).c_str(),
                              wrapped_name.c_str());
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
    std::unique_ptr<File> fp;

    process_possible_long_name(
        path,
        (flags & O_CREAT) ? LongNameComponentAction::kCreate : LongNameComponentAction::kIgnore,
        [&](std::string&& enc_path)
        { fp = std::make_unique<File>(root_->open_file_stream(enc_path, flags, mode), *opener_); });

    if (flags & O_TRUNC)
    {
        LockGuard<File> lock_guard(*fp, true);
        fp->resize(0);
    }
    return fp;
}
std::string FuseHighLevelOps::long_name_table_file_name(absl::string_view enc_path)
{
    return root_->norm_path_narrowed(
        absl::StrCat(name_trans_->remove_last_component(enc_path), "/", kLongNameTableFileName));
}
void FuseHighLevelOps::process_possible_long_name(
    absl::string_view path,
    LongNameComponentAction action,
    absl::FunctionRef<void(std::string&& enc_path)> callback)
{
    if (action == LongNameComponentAction::kIgnore)
    {
        callback(name_trans_->encrypt_full_path(path, nullptr));
        return;
    }
    std::string encrypted_last_component, enc_path;
    enc_path = name_trans_->encrypt_full_path(path, &encrypted_last_component);

    if (encrypted_last_component.empty())
    {
        callback(std::move(enc_path));
        return;
    }
    LongNameLookupTable table(long_name_table_file_name(enc_path), false);
    // Open a transaction so that we will rollback properly if the following operations fail.
    LockGuard<LongNameLookupTable> table_lg(table);
    switch (action)
    {
    case LongNameComponentAction::kCreate:
        table.update_mapping(name_trans_->get_last_component(enc_path), encrypted_last_component);
        break;
    case LongNameComponentAction::kDelete:
        table.remove_mapping(name_trans_->get_last_component(enc_path));
        break;
    default:
        throw_runtime_error("Unspecified action");
    }
    callback(std::move(enc_path));
}

std::shared_ptr<NameTranslator>
make_name_translator(const NameNormalizationFlags& flags,
                     const StrongType<key_type, tNameMasterKey>& name_master_key)
{
    if (flags.no_op)
    {
        return std::make_shared<NoOpNameTranslator>();
    }
    std::shared_ptr<NameTranslator> inner;
    if (flags.long_name_threshold > 0)
    {
        inner = std::make_shared<NewStyleNameTranslator>(
            name_master_key.get(), flags.long_name_threshold, flags.long_name_suffix);
    }
    else
    {
        inner = std::make_shared<LegacyNameTranslator>(name_master_key.get());
    }
    if (flags.should_case_fold || flags.should_normalize_nfc)
    {
        return std::make_shared<PathNormalizingNameTranslator>(
            inner, flags.should_case_fold, flags.should_normalize_nfc);
    }
    return inner;
}

std::string_view NameTranslator::get_last_component(std::string_view path)
{
    return path.substr(path.rfind('/') + 1);
}

std::string_view NameTranslator::remove_last_component(std::string_view path)
{
    return path.substr(0, path.rfind('/') + 1);
}

void change_long_name_suffix(const std::string& data_dir,
                             DecryptedSecurefsParams& mutable_params,
                             const std::string& new_long_name_suffix)
{
    if (new_long_name_suffix.empty())
    {
        throwInvalidArgumentException("new_long_name_suffix cannot be empty");
    }
    std::string_view old_suffix = mutable_params.lite_format_params().long_name_suffix();
    if (old_suffix.empty())
    {
        old_suffix = NewStyleNameTranslator::kLegacyLongNameSuffix;
    }
    if (old_suffix == new_long_name_suffix)
    {
        return;
    }

    OSService root(data_dir);
    std::vector<std::string> dirs_with_long_name_table;
    root.recursive_traverse(".",
                            [&](const std::string& dir, const std::string& name, int)
                            {
                                if (name == kLongNameTableFileName)
                                {
                                    dirs_with_long_name_table.push_back(dir);
                                }
                            });

    for (const auto& dir : dirs_with_long_name_table)
    {
        auto full_dir_name = root.norm_path_narrowed(dir);
        auto full_table_file_name
            = root.norm_path_narrowed(absl::StrCat(dir, "/", kLongNameTableFileName));

        LongNameLookupTable table(full_table_file_name, false);
        LockGuard<LongNameLookupTable> lg(table);
        auto hashes = table.list_hashes();
        for (const auto& hash : hashes)
        {
            if (!absl::EndsWith(hash, old_suffix))
            {
                continue;
            }
            auto new_hash = absl::StrCat(hash.substr(0, hash.size() - old_suffix.size()),
                                         new_long_name_suffix);
            auto old_value = table.lookup(hash);
            table.update_mapping(new_hash, old_value);
            table.remove_mapping(hash);
            root.rename(absl::StrCat(dir, "/", hash), absl::StrCat(dir, "/", new_hash));
        }
    }

    mutable_params.mutable_lite_format_params()->set_long_name_suffix(new_long_name_suffix);
}
}    // namespace securefs::lite_format
