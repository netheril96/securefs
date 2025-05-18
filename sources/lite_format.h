#pragma once

#include "crypto.h"
#include "fuse_high_level_ops_base.h"
#include "lite_stream.h"
#include "lock_guard.h"
#include "mystring.h"
#include "myutils.h"
#include "platform.h"
#include "tags.h"
#include "thread_local.h"

#include <absl/functional/function_ref.h>
#include <absl/strings/string_view.h>
#include <array>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/modes.h>
#include <cstddef>
#include <exception>

#include <memory>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace securefs::lite_format
{
constexpr std::string_view kLongNameTableFileName = ".long_names.db";
class StreamOpener : public lite::AESGCMCryptStream::ParamCalculator
{
private:
    StreamOpener(const key_type& content_master_key,
                 const key_type& padding_master_key,
                 unsigned block_size,
                 unsigned iv_size,
                 unsigned max_padding_size,
                 bool verify)
        : content_master_key_(content_master_key)
        , padding_master_key_(padding_master_key)
        , block_size_(block_size)
        , iv_size_(iv_size)
        , max_padding_size_(max_padding_size)
        , verify_(verify)
        , content_ecb(
              [this]() {
                  return std::make_unique<AES_ECB>(content_master_key_.data(),
                                                   content_master_key_.size());
              })
        , padding_ecb(
              [this]() {
                  return std::make_unique<AES_ECB>(padding_master_key_.data(),
                                                   padding_master_key_.size());
              })
    {
        validate();
    }

public:
    StreamOpener(const StrongType<key_type, tContentMasterKey>& content_master_key,
                 const StrongType<key_type, tPaddingMasterKey>& padding_master_key,
                 StrongType<unsigned, tBlockSize> block_size,
                 StrongType<unsigned, tIvSize> iv_size,
                 StrongType<unsigned, tMaxPaddingSize> max_padding_size,
                 StrongType<bool, tVerify> verify)
        : StreamOpener(content_master_key.get(),
                       padding_master_key.get(),
                       block_size.get(),
                       iv_size.get(),
                       max_padding_size.get(),
                       verify.get())
    {
    }

    std::unique_ptr<securefs::lite::AESGCMCryptStream> open(std::shared_ptr<StreamBase> base);

    length_type compute_virtual_size(length_type physical_size) const noexcept
    {
        return lite::AESGCMCryptStream::calculate_real_size(physical_size, block_size_, iv_size_);
    }

    bool can_compute_virtual_size() const noexcept { return max_padding_size_ <= 0; }

    void compute_session_key(const std::array<unsigned char, 16>& id,
                             std::array<unsigned char, 16>& outkey) override;
    unsigned compute_padding(const std::array<unsigned char, 16>& id) override;

private:
    using AES_ECB = CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption;
    void validate();

private:
    key_type content_master_key_, padding_master_key_;
    unsigned block_size_, iv_size_, max_padding_size_;
    bool verify_;
    ThreadLocal<AES_ECB> content_ecb, padding_ecb;
};

class File;
class Directory;

class ABSL_LOCKABLE Base : public Object
{
public:
    virtual File* as_file() noexcept { return nullptr; }
    virtual Directory* as_dir() noexcept { return nullptr; }
    virtual void lock(bool exclusive = true) ABSL_EXCLUSIVE_LOCK_FUNCTION() = 0;
    virtual void unlock() noexcept ABSL_UNLOCK_FUNCTION() = 0;
    virtual void fstat(fuse_stat* stat) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) = 0;
};

class ABSL_LOCKABLE Directory : public Base, public DirectoryTraverser
{
private:
    securefs::Mutex m_lock;

public:
    void lock(bool exclusive = true) override ABSL_EXCLUSIVE_LOCK_FUNCTION() { m_lock.Lock(); }
    void unlock() noexcept override ABSL_UNLOCK_FUNCTION() { m_lock.Unlock(); }
    Directory* as_dir() noexcept override { return this; }

    // Redeclare the methods in `DirectoryTraverser` to add thread safe annotations.
    bool next(std::string* name, fuse_stat* st) override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) = 0;
    void rewind() override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) = 0;
};

class ABSL_LOCKABLE File final : public Base
{
private:
    std::unique_ptr<lite::AESGCMCryptStream> m_crypt_stream ABSL_GUARDED_BY(*this);
    std::shared_ptr<securefs::FileStream> m_file_stream ABSL_GUARDED_BY(*this);
    securefs::Mutex m_lock;

public:
    File(std::shared_ptr<securefs::FileStream> file_stream, StreamOpener& opener)
        : m_file_stream(std::move(file_stream))
    {
        LockGuard<FileStream> lock_guard(*m_file_stream, true);
        m_crypt_stream = opener.open(m_file_stream);
    }

    ~File() = default;

    length_type size() const ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) { return m_crypt_stream->size(); }
    void flush() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) { m_crypt_stream->flush(); }
    bool is_sparse() const noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        return m_crypt_stream->is_sparse();
    }
    void resize(length_type len) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        m_crypt_stream->resize(len);
    }
    length_type read(void* output, offset_type off, length_type len)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        return m_crypt_stream->read(output, off, len);
    }
    void write(const void* input, offset_type off, length_type len)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        return m_crypt_stream->write(input, off, len);
    }
    void fstat(fuse_stat* stat) override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        m_file_stream->fstat(stat);
        stat->st_size = m_crypt_stream->size();
    }
    void fsync() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) { m_file_stream->fsync(); }
    void utimens(const fuse_timespec ts[2]) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        m_file_stream->utimens(ts);
    }
    void lock(bool exclusive = true) override ABSL_EXCLUSIVE_LOCK_FUNCTION()
    {
        m_lock.Lock();
        try
        {
            m_file_stream->lock(exclusive);
        }
        catch (...)
        {
            m_lock.Unlock();
            throw;
        }
    }
    void unlock() noexcept override ABSL_UNLOCK_FUNCTION()
    {
        m_file_stream->unlock();
        m_lock.Unlock();
    }
    File* as_file() noexcept override { return this; }
};

struct InvalidNameTag
{
};
struct LongNameTag
{
};

struct NameTranslator : public Object
{
    virtual bool is_no_op() const noexcept { return false; }
    /// @brief Encrypt the full path.
    /// @param path The original path.
    /// @param out_encrypted_last_component If it is not null, and the last path component is a
    /// long component, then this contains the encrypted version of the last path component.
    /// @return Encrypted path.
    virtual std::string encrypt_full_path(std::string_view path,
                                          std::string* out_encrypted_last_component)
        = 0;

    /// @brief Decrypt a component of an encrypted path.
    virtual std::variant<InvalidNameTag, LongNameTag, std::string>
    decrypt_path_component(std::string_view path) = 0;

    virtual std::string encrypt_path_for_symlink(std::string_view path) = 0;
    virtual std::string decrypt_path_from_symlink(std::string_view path) = 0;

    virtual unsigned max_virtual_path_component_size(unsigned physical_path_component_size) = 0;

    static std::string_view get_last_component(std::string_view path);
    static std::string_view remove_last_component(std::string_view path);
};

struct NameNormalizationFlags
{
    bool no_op;
    bool should_case_fold;
    bool should_normalize_nfc;
    unsigned long_name_threshold;
};

std::shared_ptr<NameTranslator>
make_name_translator(const NameNormalizationFlags& flags,
                     const StrongType<key_type, tNameMasterKey>& name_master_key);

class XattrVerificationException : public std::exception
{
public:
    const char* what() const noexcept override { return "Xattr decryption failed verification"; }
};

class XattrCryptor
{
private:
    XattrCryptor(const key_type& key, unsigned iv_size, bool verify)
        : crypt_([key]() { return std::make_unique<Cryptor>(key); })
        , iv_size_(iv_size)
        , verify_(verify)
    {
    }

public:
    // Added constructor with StrongType arguments
    XattrCryptor(const StrongType<key_type, tXattrMasterKey>& key,
                 StrongType<unsigned, tIvSize> iv_size,
                 StrongType<bool, tVerify> verify)
        : XattrCryptor(key.get(), iv_size.get(), verify.get())
    {
    }

    std::vector<byte> encrypt(const char* value, size_t size);
    void decrypt(const byte* input, size_t size, byte* output, size_t out_size);
    size_t infer_decrypted_size(size_t encrypted_size);
    size_t infer_encrypted_size(size_t decrypted_size);

    static constexpr unsigned kMacSize = 16;

private:
    struct Cryptor
    {
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;

        explicit Cryptor(const key_type& key)
        {
            const std::array<byte, 12> null_iv{};
            enc.SetKeyWithIV(key.data(), key.size(), null_iv.data(), null_iv.size());
            dec.SetKeyWithIV(key.data(), key.size(), null_iv.data(), null_iv.size());
        }
    };

    ThreadLocal<Cryptor> crypt_;
    unsigned iv_size_;
    bool verify_;
};

class FuseHighLevelOps : public ::securefs::FuseHighLevelOpsBase
{
private:
    FuseHighLevelOps(std::shared_ptr<::securefs::OSService> root,
                     std::shared_ptr<StreamOpener> opener,
                     std::shared_ptr<NameTranslator> name_trans,
                     std::shared_ptr<XattrCryptor> xattr,
                     const key_type& xattr_key,
                     bool enable_xattr)
        : root_(std::move(root))
        , opener_(std::move(opener))
        , name_trans_(std::move(name_trans))
        , xattr_(std::move(xattr))
        , enable_xattr_(enable_xattr)
    {
        if (!is_apple())
        {
            xattr_name_cryptor_.emplace(xattr_key.data(), xattr_key.size());
        }
    }

public:
    // Added constructor with StrongType arguments
    FuseHighLevelOps(std::shared_ptr<::securefs::OSService> root,
                     std::shared_ptr<StreamOpener> opener,
                     std::shared_ptr<NameTranslator> name_trans,
                     std::shared_ptr<XattrCryptor> xattr,
                     const StrongType<key_type, tXattrMasterKey>& xattr_key,
                     StrongType<bool, tEnableXattr> enable_xattr)
        : FuseHighLevelOps(std::move(root),
                           std::move(opener),
                           std::move(name_trans),
                           std::move(xattr),
                           xattr_key.get(),
                           enable_xattr.get())
    {
    }

    bool has_symlink() const override { return !is_windows(); }
    bool has_readlink() const override { return !is_windows(); }
    bool has_link() const override { return !is_windows(); }
    bool has_chmod() const override { return !is_windows(); }
    bool has_chown() const override { return !is_windows(); }

    bool has_listxattr() const override { return enable_xattr_; }
    bool has_getxattr() const override { return enable_xattr_; }
    bool has_setxattr() const override { return enable_xattr_; }
    bool has_removexattr() const override { return enable_xattr_; }

    void initialize(fuse_conn_info* info) override;
    int vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx) override;
    int vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx) override;
    int vfgetattr(const char* path,
                  fuse_stat* st,
                  fuse_file_info* info,
                  const fuse_context* ctx) override;
    int vopendir(const char* path, fuse_file_info* info, const fuse_context* ctx) override;
    int vreleasedir(const char* path, fuse_file_info* info, const fuse_context* ctx) override;
    int vreaddir(const char* path,
                 void* buf,
                 fuse_fill_dir_t filler,
                 fuse_off_t off,
                 fuse_file_info* info,
                 const fuse_context* ctx) override;
    int vcreate(const char* path,
                fuse_mode_t mode,
                fuse_file_info* info,
                const fuse_context* ctx) override;
    int vopen(const char* path, fuse_file_info* info, const fuse_context* ctx) override;
    int vrelease(const char* path, fuse_file_info* info, const fuse_context* ctx) override;
    int vread(const char* path,
              char* buf,
              size_t size,
              fuse_off_t offset,
              fuse_file_info* info,
              const fuse_context* ctx) override;
    int vwrite(const char* path,
               const char* buf,
               size_t size,
               fuse_off_t offset,
               fuse_file_info* info,
               const fuse_context* ctx) override;
    int vflush(const char* path, fuse_file_info* info, const fuse_context* ctx) override;
    int vftruncate(const char* path,
                   fuse_off_t len,
                   fuse_file_info* info,
                   const fuse_context* ctx) override;
    int vunlink(const char* path, const fuse_context* ctx) override;
    int vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx) override;
    int vrmdir(const char* path, const fuse_context* ctx) override;
    int vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx) override;
    int vchown(const char* path, fuse_uid_t uid, fuse_gid_t gid, const fuse_context* ctx) override;
    int vsymlink(const char* to, const char* from, const fuse_context* ctx) override;
    int vlink(const char* src, const char* dest, const fuse_context* ctx) override;
    int vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx) override;
    int vrename(const char* from, const char* to, const fuse_context* ctx) override;
    int
    vfsync(const char* path, int datasync, fuse_file_info* info, const fuse_context* ctx) override;
    int vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx) override;
    int vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx) override;
    int vlistxattr(const char* path, char* list, size_t size, const fuse_context* ctx) override;
    int vgetxattr(const char* path,
                  const char* name,
                  char* value,
                  size_t size,
                  uint32_t position,
                  const fuse_context* ctx) override;
    int vsetxattr(const char* path,
                  const char* name,
                  const char* value,
                  size_t size,
                  int flags,
                  uint32_t position,
                  const fuse_context* ctx) override;
    int vremovexattr(const char* path, const char* name, const fuse_context* ctx) override;

private:
    std::shared_ptr<::securefs::OSService> root_;
    std::shared_ptr<StreamOpener> opener_;
    std::shared_ptr<NameTranslator> name_trans_;
    std::shared_ptr<XattrCryptor> xattr_;
    std::optional<AES_SIV> xattr_name_cryptor_;
    bool enable_xattr_;
    bool read_dir_plus_ = false;

private:
    std::unique_ptr<File> open(std::string_view path, int flags, unsigned mode);

    enum class LongNameComponentAction : unsigned char
    {
        kCreate = 0,
        kDelete = 1,
        kIgnore = 2,
    };

    void process_possible_long_name(absl::string_view path,
                                    LongNameComponentAction action,
                                    absl::FunctionRef<void(std::string&& enc_path)> callback);

    std::string long_name_table_file_name(absl::string_view enc_path);
};
}    // namespace securefs::lite_format
