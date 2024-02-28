#pragma once

#include "constants.h"
#include "crypto.h"
#include "lite_stream.h"
#include "lock_guard.h"
#include "mystring.h"
#include "myutils.h"
#include "platform.h"

#include <absl/base/thread_annotations.h>
#include <absl/strings/string_view.h>
#include <absl/types/span.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/secblock.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace securefs
{
namespace lite
{
    class File;
    class Directory;

    class Base
    {
    public:
        Base() {}
        virtual ~Base() = 0;
        virtual File* as_file() noexcept { return nullptr; }
        virtual Directory* as_dir() noexcept { return nullptr; }
    };

    class ABSL_LOCKABLE Directory : public Base, public DirectoryTraverser
    {
    private:
        securefs::Mutex m_lock;

    public:
        void lock() ABSL_EXCLUSIVE_LOCK_FUNCTION() { m_lock.lock(); }
        void unlock() noexcept ABSL_UNLOCK_FUNCTION() { m_lock.unlock(); }
        Directory* as_dir() noexcept { return this; }

        // Obtains the (virtual) path of the directory.
        virtual absl::string_view path() const = 0;

        // Redeclare the methods in `DirectoryTraverser` to add thread safe annotations.
        virtual bool next(std::string* name, struct fuse_stat* st)
            ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
            = 0;
        virtual void rewind() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) = 0;
    };

    class ABSL_LOCKABLE File final : public Base
    {
        DISABLE_COPY_MOVE(File)

    private:
        securefs::optional<lite::AESGCMCryptStream> m_crypt_stream ABSL_GUARDED_BY(*this);
        std::shared_ptr<securefs::FileStream> m_file_stream ABSL_GUARDED_BY(*this);
        securefs::Mutex m_lock;

    public:
        template <typename... Args>
        File(std::shared_ptr<securefs::FileStream> file_stream, Args&&... args)
            : m_file_stream(file_stream)
        {
            LockGuard<FileStream> lock_guard(*m_file_stream, true);
            m_crypt_stream.emplace(file_stream, std::forward<Args>(args)...);
        }

        ~File();

        length_type size() const ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
        {
            return m_crypt_stream->size();
        }
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
        void fstat(struct fuse_stat* stat) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
        void fsync() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) { m_file_stream->fsync(); }
        void utimens(const fuse_timespec ts[2]) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
        {
            m_file_stream->utimens(ts);
        }
        void lock(bool exclusive = true) ABSL_EXCLUSIVE_LOCK_FUNCTION()
        {
            m_lock.lock();
            try
            {
                m_file_stream->lock(exclusive);
            }
            catch (...)
            {
                m_lock.unlock();
                throw;
            }
        }
        void unlock() noexcept ABSL_UNLOCK_FUNCTION()
        {
            m_file_stream->unlock();
            m_lock.unlock();
        }
        File* as_file() noexcept override { return this; }
    };

    class FileSystem;

    typedef std::unique_ptr<File> AutoClosedFile;

    std::string legacy_encrypt_path(AES_SIV& encryptor, absl::string_view path);
    std::string legacy_decrypt_path(AES_SIV& decryptor, absl::string_view path);

    class InvalidFilenameException : public VerificationException
    {
    private:
        std::string m_filename;

    public:
        explicit InvalidFilenameException(std::string filename) : m_filename(filename) {}
        ~InvalidFilenameException();

        std::string message() const override;
        int error_number() const noexcept override { return EINVAL; }
    };

    class FileSystem
    {
        DISABLE_COPY_MOVE(FileSystem)

    private:
        std::shared_ptr<AES_SIV> m_name_encryptor;
        key_type m_content_key;
        CryptoPP::GCM<CryptoPP::AES>::Encryption m_xattr_enc;
        CryptoPP::GCM<CryptoPP::AES>::Decryption m_xattr_dec;
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption m_padding_aes;
        std::shared_ptr<const securefs::OSService> m_root;
        unsigned m_block_size, m_iv_size, m_max_padding_size;
        unsigned m_flags;

    private:
        std::string translate_path(absl::string_view path, bool preserve_leading_slash);

        static std::string legacy_encrypt_symlink(absl::string_view path);
        static std::string legacy_decrypt_symlink(absl::string_view path);

        static std::string new_encrypt_symlink(absl::string_view path);
        static std::string new_decrypt_symlink(absl::string_view path);

    public:
        FileSystem(std::shared_ptr<const securefs::OSService> root,
                   const key_type& name_key,
                   const key_type& content_key,
                   const key_type& xattr_key,
                   const key_type& padding_key,
                   unsigned block_size,
                   unsigned iv_size,
                   unsigned max_padding_size,
                   unsigned flags);

        ~FileSystem();

        AutoClosedFile open(absl::string_view path, int flags, fuse_mode_t mode);
        bool stat(absl::string_view path, struct fuse_stat* buf);
        void mkdir(absl::string_view path, fuse_mode_t mode);
        void rmdir(absl::string_view path);
        void chmod(absl::string_view path, fuse_mode_t mode);
        void chown(absl::string_view path, fuse_uid_t uid, fuse_gid_t gid);
        void rename(absl::string_view from, absl::string_view to);
        void unlink(absl::string_view path);
        void symlink(absl::string_view to, absl::string_view from);
        void link(absl::string_view src, absl::string_view dest);
        size_t readlink(absl::string_view path, char* buf, size_t size);
        void utimens(absl::string_view path, const fuse_timespec tm[2]);
        void statvfs(struct fuse_statvfs* buf);
        std::unique_ptr<Directory> opendir(absl::string_view path);

        bool has_padding() const noexcept { return m_max_padding_size > 0; }
        bool skip_dot_dot() const noexcept { return m_flags & kOptionSkipDotDot; }
        bool supports_long_name() const noexcept { return m_flags & kOptionLongNameComponent; }

#ifdef __APPLE__
        // These APIs, unlike all others, report errors through negative error numbers as defined in
        // <errno.h>
        ssize_t listxattr(const char* path, char* buf, size_t size) noexcept
        {
            return m_root->listxattr(translate_path(path, false).c_str(), buf, size);
        }
        ssize_t getxattr(const char* path, const char* name, void* buf, size_t size) noexcept;
        int
        setxattr(const char* path, const char* name, void* buf, size_t size, int flags) noexcept;
        int removexattr(const char* path, const char* name) noexcept
        {
            return m_root->removexattr(translate_path(path, false).c_str(), name);
        }
#endif
    };
}    // namespace lite
}    // namespace securefs
