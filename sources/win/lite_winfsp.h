#pragma once

#include "lite_format.h"
#include "nt_stream.h"
#include "params.pb.h"
#include "smart_handle.h"
#include "winfsp_wrappers.h"

namespace securefs::lite_format
{
class LiteWinFspFileSystem final : public WinFspFileSystem
{
public:
    LiteWinFspFileSystem(UniqueHandle root,
                         std::shared_ptr<StreamOpener> opener,
                         std::shared_ptr<NameTranslator> name_trans,
                         const MountOptions_WinFspMountOptions& opt);
    ~LiteWinFspFileSystem() override;

    NTSTATUS vGetSecurityByName(PWSTR FileName,
                                PUINT32 PFileAttributes,
                                PSECURITY_DESCRIPTOR SecurityDescriptor,
                                SIZE_T* PSecurityDescriptorSize) override;
    bool has_GetSecurityByName() const override { return true; }

    const FSP_FSCTL_VOLUME_PARAMS& GetVolumeParams() const override { return m_params; }

    NTSTATUS vOpen(PWSTR FileName,
                   UINT32 CreateOptions,
                   UINT32 GrantedAccess,
                   PVOID* PFileContext,
                   FSP_FSCTL_FILE_INFO* FileInfo) override;
    bool has_Open() const override { return true; }

    VOID vClose(PVOID FileContext) override;
    bool has_Close() const override { return true; }

    NTSTATUS vRead(PVOID FileContext,
                   PVOID Buffer,
                   UINT64 Offset,
                   ULONG Length,
                   PULONG PBytesTransferred) override;
    bool has_Read() const override { return true; }

    NTSTATUS vReadDirectory(PVOID FileContext,
                            PWSTR Pattern,
                            PWSTR Marker,
                            PVOID Buffer,
                            ULONG Length,
                            PULONG PBytesTransferred) override;
    bool has_ReadDirectory() const override { return true; }

private:
    FSP_FSCTL_VOLUME_PARAMS m_params{};

    UniqueHandle m_root{};
    std::shared_ptr<StreamOpener> opener_{};
    std::shared_ptr<NameTranslator> name_trans_{};

private:
    void init_volume_params(const MountOptions_WinFspMountOptions& opt);
    std::wstring translate_name(std::wstring_view filename);
};

class LiteNTFile;
class LiteNTDirectory;

class ABSL_LOCKABLE LiteNTBase : public Object
{
public:
    virtual LiteNTFile* as_file() noexcept { return nullptr; }
    virtual LiteNTDirectory* as_dir() noexcept { return nullptr; }
    virtual void lock(bool exclusive = true) ABSL_EXCLUSIVE_LOCK_FUNCTION() = 0;
    virtual void unlock() noexcept ABSL_UNLOCK_FUNCTION() = 0;
};

class ABSL_LOCKABLE LiteNTDirectory : public LiteNTBase
{
private:
    securefs::Mutex m_lock;

public:
    LiteNTDirectory* as_dir() noexcept override { return this; }
};

class ABSL_LOCKABLE LiteNTFile final : public LiteNTBase
{
private:
    std::unique_ptr<lite::AESGCMCryptStream> m_crypt_stream ABSL_GUARDED_BY(*this);
    std::shared_ptr<NTStream> m_file_stream ABSL_GUARDED_BY(*this);
    securefs::Mutex m_lock;

public:
    LiteNTFile(std::shared_ptr<securefs::NTStream> file_stream, StreamOpener& opener)
        : m_file_stream(std::move(file_stream))
    {
        LockGuard<securefs::NTStream> lock_guard(*m_file_stream, true);
        m_crypt_stream = opener.open(m_file_stream);
    }

    ~LiteNTFile() = default;

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
    LiteNTFile* as_file() noexcept override { return this; }
};

}    // namespace securefs::lite_format
