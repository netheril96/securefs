#pragma once

#include "lite_format.h"
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
}    // namespace securefs::lite_format
