#pragma once

#include "aes_siv.h"
#include "lite_stream.h"
#include "myutils.h"
#include "platform.h"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <cryptopp/aes.h>
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
        AESGCMCryptStream m_crypt_stream;
        std::mutex m_mutex;
        std::string m_name;
        std::shared_ptr<securefs::FileStream> m_file_stream;
        std::atomic<int> m_open_count;

    public:
        explicit File(std::string name,
                      std::shared_ptr<securefs::FileStream> file_stream,
                      const key_type& master_key,
                      unsigned block_size,
                      unsigned iv_size,
                      bool check);
        ~File();

        length_type size() const { return m_crypt_stream.size(); }
        void flush() { m_crypt_stream.flush(); }
        bool is_sparse() const noexcept { return m_crypt_stream.is_sparse(); }
        void resize(length_type len) { m_crypt_stream.resize(len); }
        length_type read(void* output, offset_type off, length_type len)
        {
            return m_crypt_stream.read(output, off, len);
        }
        void write(const void* input, offset_type off, length_type len)
        {
            return m_crypt_stream.write(input, off, len);
        }
        void fstat(FUSE_STAT* stat);
        void fsync() { m_file_stream->fsync(); }
        void utimens(const timespec ts[2]) { m_file_stream->utimens(ts); }
        int increase_open_count() noexcept { return ++m_open_count; }
        int decrease_open_count() noexcept { return --m_open_count; }
        void lock() { m_mutex.lock(); }
        void unlock() { m_mutex.unlock(); }
        bool try_lock() { return m_mutex.try_lock(); }
        const std::string& name() const noexcept { return m_name; }
    };

    class FileSystem;

    struct FSCCloser
    {
    private:
        FileSystem* m_ctx;

    public:
        explicit FSCCloser(FileSystem* ctx) : m_ctx(ctx) {}
        ~FSCCloser() {}
        void operator()(File* file);
    };

    typedef std::unique_ptr<File, FSCCloser> AutoClosedFile;

    std::string encrypt_path(AES_SIV& encryptor, const std::string& path);
    std::string decrypt_path(AES_SIV& decryptor, const std::string& path);

    class InvalidFilenameException : public VerificationException
    {
    private:
        std::string m_filename;

    public:
        explicit InvalidFilenameException(std::string filename) : m_filename(filename) {}
        ~InvalidFilenameException();
        const char* type_name() const noexcept override { return "InvalidFilenameException"; }
        std::string message() const override;
        int error_number() const noexcept override { return EINVAL; }
    };

    class FileSystem
    {
        DISABLE_COPY_MOVE(FileSystem)

    private:
        std::map<std::string, File*> m_opened_files;
        std::map<std::string, std::string> m_resolved_symlinks;
        std::mutex m_mutex;
        AES_SIV m_name_encryptor;
        key_type m_content_key;
        CryptoPP::GCM<CryptoPP::AES>::Encryption m_xattr_enc;
        CryptoPP::GCM<CryptoPP::AES>::Decryption m_xattr_dec;
        std::shared_ptr<securefs::OSService> m_root;
        unsigned m_block_size, m_iv_size;
        bool m_check;

    private:
        std::string translate_path(const std::string& path, bool preserve_leading_slash);

    public:
        FileSystem(std::shared_ptr<securefs::OSService> root,
                   const key_type& name_key,
                   const key_type& content_key,
                   const key_type& xattr_key,
                   unsigned block_size,
                   unsigned iv_size,
                   bool check);
        ~FileSystem();

        void lock() { m_mutex.lock(); }
        void unlock() { m_mutex.unlock(); }
        bool try_lock() { return m_mutex.try_lock(); }
        void close(File* f);
        AutoClosedFile open(const std::string& path, int flags);
        AutoClosedFile create(const std::string& path, mode_t mode);
        bool stat(const std::string& path, FUSE_STAT* buf);
        void mkdir(const std::string& path, mode_t mode);
        void rmdir(const std::string& path);
        void chmod(const std::string& path, mode_t mode);
        void rename(const std::string& from, const std::string& to);
        void unlink(const std::string& path);
        void symlink(const std::string& to, const std::string& from);
        size_t readlink(const std::string& path, char* buf, size_t size);
        void utimens(const std::string& path, const timespec tm[2]);
        void truncate(const std::string& path, offset_type len);
        void statvfs(struct statvfs* buf);
        void
        traverse_directory(const std::string& path,
                           const OSService::traverse_callback& callback,
                           const std::function<void(const std::string&)> decoding_error_handler);
    };

    inline void FSCCloser::operator()(File* file) { m_ctx->close(file); }
}
}
