#pragma once

#include "lite_stream.h"
#include "lock_guard.h"
#include "platform.h"
#include "tags.h"
#include "thread_local.h"

#include <cryptopp/aes.h>
#include <fruit/fruit.h>

namespace securefs
{
namespace lite_format
{
    class StreamOpener : public lite::AESGCMCryptStream::ParamCalculator
    {
    public:
        INJECT(StreamOpener(ANNOTATED(tContentMasterKey, key_type) content_master_key,
                            ANNOTATED(tPaddingMasterKey, key_type) padding_master_key,
                            ANNOTATED(tBlockSize, unsigned) block_size,
                            ANNOTATED(tIvSize, unsigned) iv_size,
                            ANNOTATED(tMaxPaddingSize, unsigned) max_padding_size,
                            ANNOTATED(tSkipVerification, bool) skip_verfication))
            : content_master_key_(content_master_key)
            , padding_master_key_(padding_master_key)
            , block_size_(block_size)
            , iv_size_(iv_size)
            , max_padding_size_(max_padding_size)
            , skip_verification_(skip_verfication)
        {
        }

        std::unique_ptr<securefs::lite::AESGCMCryptStream> open(std::shared_ptr<StreamBase> base);

        virtual void compute_session_key(const std::array<unsigned char, 16>& id,
                                         std::array<unsigned char, 16>& outkey) override;
        virtual unsigned compute_padding(const std::array<unsigned char, 16>& id) override;

    private:
        using AES_ECB = CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption;
        AES_ECB& get_thread_local_content_master_enc();
        AES_ECB& get_thread_local_padding_master_enc();

    private:
        key_type content_master_key_, padding_master_key_;
        unsigned block_size_, iv_size_, max_padding_size_;
        bool skip_verification_;
        ThreadLocal content_ecb, padding_ecb;
    };

    class File;
    class Directory;

    class Base : public Object
    {
    public:
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
        virtual bool next(std::string* name, fuse_stat* st) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
            = 0;
        virtual void rewind() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) = 0;
    };

    class ABSL_LOCKABLE File final : public Base
    {
    private:
        std::unique_ptr<lite::AESGCMCryptStream> m_crypt_stream ABSL_GUARDED_BY(*this);
        std::shared_ptr<securefs::FileStream> m_file_stream ABSL_GUARDED_BY(*this);
        securefs::Mutex m_lock;

    public:
        File(std::shared_ptr<securefs::FileStream> file_stream, StreamOpener& opener)
            : m_file_stream(file_stream)
        {
            LockGuard<FileStream> lock_guard(*m_file_stream, true);
            m_crypt_stream = opener.open(file_stream);
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
        void fstat(fuse_stat* stat) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
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

}    // namespace lite_format

}    // namespace securefs
