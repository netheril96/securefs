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
