#pragma once

#include "aes_siv.h"
#include "lite_stream.h"
#include "mystring.h"
#include "myutils.h"
#include "platform.h"

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/base32.h>
#include <cryptopp/gcm.h>
#include <cryptopp/secblock.h>

namespace securefs
{
namespace lite
{
    class File
    {
        DISABLE_COPY_MOVE(File)

    private:
        securefs::optional<lite::AESGCMCryptStream> m_crypt_stream;
        std::shared_ptr<securefs::FileStream> m_file_stream;
        std::mutex m_lock;

    public:
        explicit File(std::shared_ptr<securefs::FileStream> file_stream,
                      const key_type& master_key,
                      unsigned block_size,
                      unsigned iv_size,
                      bool check);
        ~File();

        length_type size() const { return m_crypt_stream->size(); }
        void flush() { m_crypt_stream->flush(); }
        bool is_sparse() const noexcept { return m_crypt_stream->is_sparse(); }
        void resize(length_type len) { m_crypt_stream->resize(len); }
        length_type read(void* output, offset_type off, length_type len)
        {
            return m_crypt_stream->read(output, off, len);
        }
        void write(const void* input, offset_type off, length_type len)
        {
            return m_crypt_stream->write(input, off, len);
        }
        void fstat(struct fuse_stat* stat);
        void fsync() { m_file_stream->fsync(); }
        void utimens(const fuse_timespec ts[2]) { m_file_stream->utimens(ts); }
        void lock(bool exclusive = true)
        {
            m_lock.lock();
            m_file_stream->lock(exclusive);
        }
        void unlock() noexcept
        {
            m_file_stream->unlock();
            m_lock.unlock();
        }
    };

    class FileSystem;

    typedef std::unique_ptr<File> AutoClosedFile;

    std::string encrypt_path(AES_SIV& encryptor, StringRef path);
    std::string decrypt_path(AES_SIV& decryptor, StringRef path);

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
        AES_SIV m_name_encryptor;
        CryptoPP::Base32Encoder m_encoder;
        key_type m_content_key;
        CryptoPP::GCM<CryptoPP::AES>::Encryption m_xattr_enc;
        CryptoPP::GCM<CryptoPP::AES>::Decryption m_xattr_dec;
        CryptoPP::AutoSeededRandomPool m_csrng;
        std::shared_ptr<const securefs::OSService> m_root;
        unsigned m_block_size, m_iv_size;
        unsigned m_flags;

    private:
        std::string translate_path(StringRef path, bool preserve_leading_slash);

    public:
        FileSystem(std::shared_ptr<const securefs::OSService> root,
                   const key_type& name_key,
                   const key_type& content_key,
                   const key_type& xattr_key,
                   unsigned block_size,
                   unsigned iv_size,
                   unsigned flags);

        ~FileSystem();

        AutoClosedFile open(StringRef path, int flags, fuse_mode_t mode);
        bool stat(StringRef path, struct fuse_stat* buf);
        void mkdir(StringRef path, fuse_mode_t mode);
        void rmdir(StringRef path);
        void chmod(StringRef path, fuse_mode_t mode);
        void rename(StringRef from, StringRef to);
        void unlink(StringRef path);
        void symlink(StringRef to, StringRef from);
        void link(StringRef src, StringRef dest);
        size_t readlink(StringRef path, char* buf, size_t size);
        void utimens(StringRef path, const fuse_timespec tm[2]);
        void statvfs(struct fuse_statvfs* buf);
        std::unique_ptr<DirectoryTraverser> create_traverser(StringRef path);

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
}
}
