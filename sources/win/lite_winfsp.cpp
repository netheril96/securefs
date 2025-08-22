#include "lite_winfsp.h"
#include "nt_exception.h"
#include "ntdecls.h"

namespace securefs::lite_format
{
LiteWinFspFileSystem::LiteWinFspFileSystem(UniqueHandle root,
                                           std::shared_ptr<StreamOpener> opener,
                                           std::shared_ptr<NameTranslator> name_trans,
                                           const MountOptions_WinFspMountOptions& opt)
    : m_root(std::move(root)), opener_(std::move(opener)), name_trans_(std::move(name_trans))
{
    init_volume_params(opt);
}

LiteWinFspFileSystem::~LiteWinFspFileSystem() = default;

void LiteWinFspFileSystem::init_volume_params(const MountOptions_WinFspMountOptions& opt)
{
    union
    {
        FILE_FS_ATTRIBUTE_INFORMATION V;
        UINT8 B[FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)
                + MAX_PATH * sizeof(WCHAR)];
    } FsAttrInfo;
    NT_CHECK_CALL(NtQueryVolumeInformationFile(m_root.get(),
                                               nullptr,
                                               &FsAttrInfo,
                                               sizeof(FsAttrInfo),
                                               /*FileFsAttributeInformation*/
                                               5));

    FILE_FS_SIZE_INFORMATION FsSizeInfo;
    NT_CHECK_CALL(NtQueryVolumeInformationFile(m_root.get(),
                                               nullptr,
                                               &FsSizeInfo,
                                               sizeof(FsSizeInfo),
                                               /*FileFsSizeInformation*/
                                               3));
    FILE_ALL_INFORMATION FileAllInfo;
    NT_CHECK_CALL(
        NtQueryInformationFile(m_root.get(),
                               nullptr,
                               &FileAllInfo,
                               sizeof(FileAllInfo),
                               /*FileAllInformation*/ static_cast<FILE_INFORMATION_CLASS>(18)));

    m_params.SectorSize = (UINT16)FsSizeInfo.BytesPerSector;
    m_params.SectorsPerAllocationUnit = (UINT16)FsSizeInfo.SectorsPerAllocationUnit;
    m_params.MaxComponentLength = (UINT16)name_trans_->max_virtual_path_component_size(
        FsAttrInfo.V.MaximumComponentNameLength);
    m_params.VolumeCreationTime = FileAllInfo.BasicInformation.CreationTime.QuadPart;
    m_params.VolumeSerialNumber = 0;
    m_params.FileInfoTimeout = opt.attr_timeout_ms() > 0 ? opt.attr_timeout_ms() : 30000;
    m_params.CaseSensitiveSearch = 1;
    m_params.CasePreservedNames = 1;
    m_params.UnicodeOnDisk = 1;
    m_params.PersistentAcls = !!(FsAttrInfo.V.FileSystemAttributes & FILE_PERSISTENT_ACLS);
    m_params.ReparsePoints
        = 0 && !!(FsAttrInfo.V.FileSystemAttributes & FILE_SUPPORTS_REPARSE_POINTS);
    m_params.NamedStreams = 0;
    m_params.ExtendedAttributes
        = 0 && !!(FsAttrInfo.V.FileSystemAttributes & FILE_SUPPORTS_EXTENDED_ATTRIBUTES);
    m_params.SupportsPosixUnlinkRename = !!(FsAttrInfo.V.FileSystemAttributes & 0x00000400
                                            /*FILE_SUPPORTS_POSIX_UNLINK_RENAME*/);
    m_params.ReadOnlyVolume = !!(FsAttrInfo.V.FileSystemAttributes & FILE_READ_ONLY_VOLUME);
    m_params.PostCleanupWhenModifiedOnly = 1;
    m_params.PostDispositionWhenNecessaryOnly = 1;
    m_params.PassQueryDirectoryPattern = 0;
    m_params.FlushAndPurgeOnCleanup = 1;
    m_params.WslFeatures = 0;
    m_params.AllowOpenInKernelMode = 1;
    m_params.RejectIrpPriorToTransact0 = 1;
    m_params.UmFileContextIsUserContext2 = 1;

    m_params.CasePreservedNames = 1;
    m_params.CaseSensitiveSearch = 1;

    auto wide_fsname = widen_string(opt.filesystem_name());
    memcpy(m_params.FileSystemName,
           wide_fsname.data(),
           std::min(wide_fsname.size() * sizeof(WCHAR), sizeof(m_params.FileSystemName) - 1));
}

NTSTATUS LiteWinFspFileSystem::vGetSecurityByName(PWSTR FileName,
                                                  PUINT32 PFileAttributes,
                                                  PSECURITY_DESCRIPTOR SecurityDescriptor,
                                                  SIZE_T* PSecurityDescriptorSize)
{
    auto underlying_name = translate_name(FileName);
    OBJECT_ATTRIBUTES obj_attr;
    UNICODE_STRING uni_name;
    InitializeObjectAttributes(&obj_attr, &uni_name, OBJ_CASE_INSENSITIVE, m_root.get(), nullptr);

    // Use the translated name as the file name
    uni_name.Buffer = underlying_name.data();
    uni_name.Length = (USHORT)(underlying_name.size() * sizeof(WCHAR));
    uni_name.MaximumLength = uni_name.Length;

    HANDLE file_handle;
    IO_STATUS_BLOCK io_status;
    NT_CHECK_CALL(NtOpenFile(&file_handle,
                             READ_CONTROL,
                             &obj_attr,
                             &io_status,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_OPEN_FOR_BACKUP_INTENT));
    DEFER(NtClose(file_handle));
    if (PSecurityDescriptorSize)
    {
        // If we successfully opened the file, query its security descriptor
        DWORD sd_size = 0;
        NT_CHECK_CALL(NtQuerySecurityObject(file_handle,
                                            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION
                                                | GROUP_SECURITY_INFORMATION,
                                            SecurityDescriptor,
                                            (ULONG)*PSecurityDescriptorSize,
                                            &sd_size));
        *PSecurityDescriptorSize = sd_size;
    }
    if (PFileAttributes)
    {
        FILE_ATTRIBUTE_TAG_INFORMATION AttrInfo;
        IO_STATUS_BLOCK IoStatusBlock;
        NT_CHECK_CALL(NtQueryInformationFile(
            file_handle,
            &IoStatusBlock,
            &AttrInfo,
            sizeof(FILE_ATTRIBUTE_TAG_INFORMATION),
            static_cast<FILE_INFORMATION_CLASS>(35) /*FileAttributeTagInformation*/));
        *PFileAttributes = AttrInfo.FileAttributes;
    }

    return 0;
}

NTSTATUS LiteWinFspFileSystem::vOpen(PWSTR FileName,
                                     UINT32 CreateOptions,
                                     UINT32 GrantedAccess,
                                     PVOID* PFileContext,
                                     FSP_FSCTL_FILE_INFO* FileInfo)
{
    // Stub implementation
    return STATUS_NOT_IMPLEMENTED;
}

VOID LiteWinFspFileSystem::vClose(PVOID FileContext)
{
    // Stub implementation
}

NTSTATUS LiteWinFspFileSystem::vRead(
    PVOID FileContext, PVOID Buffer, UINT64 Offset, ULONG Length, PULONG PBytesTransferred)
{
    // Stub implementation
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS LiteWinFspFileSystem::vReadDirectory(PVOID FileContext,
                                              PWSTR Pattern,
                                              PWSTR Marker,
                                              PVOID Buffer,
                                              ULONG Length,
                                              PULONG PBytesTransferred)
{
    // Stub implementation
    return STATUS_NOT_IMPLEMENTED;
}

std::wstring LiteWinFspFileSystem::translate_name(std::wstring_view filename)
{
    // Stub for now.
    return {filename.data(), filename.size()};
}

}    // namespace securefs::lite_format
