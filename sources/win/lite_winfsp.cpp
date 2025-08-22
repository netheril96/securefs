#include "lite_winfsp.h"
#include "nt_exception.h"
#include "ntdecls.h"
#include "nt_directory_iterator.h"

namespace securefs::lite_format
{

namespace
{
    FSP_FSCTL_FILE_INFO read_file_info_from_handle(HANDLE handle)
    {
        constexpr ULONG AllInfoBufferSize = 4000;

        IO_STATUS_BLOCK Iosb;
        auto AllInfo = static_cast<FILE_ALL_INFORMATION*>(malloc(AllInfoBufferSize));
        if (!AllInfo)
        {
            throw std::bad_alloc();
        }

        NT_CHECK_CALL(
            NtQueryInformationFile(handle,
                                   &Iosb,
                                   AllInfo,
                                   AllInfoBufferSize,
                                   static_cast<FILE_INFORMATION_CLASS>(18) /*FileAllInformation*/));

        FSP_FSCTL_FILE_INFO info;
        memset(&info, 0, sizeof(info));

        info.FileAttributes = AllInfo->BasicInformation.FileAttributes;
        info.AllocationSize = AllInfo->StandardInformation.AllocationSize.QuadPart;
        info.FileSize = AllInfo->StandardInformation.EndOfFile.QuadPart;
        info.CreationTime = AllInfo->BasicInformation.CreationTime.QuadPart;
        info.LastAccessTime = AllInfo->BasicInformation.LastAccessTime.QuadPart;
        info.LastWriteTime = AllInfo->BasicInformation.LastWriteTime.QuadPart;
        info.ChangeTime = AllInfo->BasicInformation.ChangeTime.QuadPart;
        info.IndexNumber = AllInfo->InternalInformation.IndexNumber.QuadPart;

        return info;
    }

    UniqueHandle open_existing_file(ACCESS_MASK DesiredAccess,
                                    HANDLE RootHandle,
                                    PCWSTR FileName,
                                    ULONG OpenOptions)
    {
        UNICODE_STRING unicode_file_name;
        OBJECT_ATTRIBUTES Obja;
        IO_STATUS_BLOCK Iosb;
        NTSTATUS Result;
        HANDLE handle;

        RtlInitUnicodeString(&unicode_file_name, FileName);
        InitializeObjectAttributes(&Obja, &unicode_file_name, OBJ_CASE_INSENSITIVE, RootHandle, 0);

        NT_CHECK_CALL(NtOpenFile(&handle,
                                 FILE_READ_ATTRIBUTES | DesiredAccess,
                                 &Obja,
                                 &Iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 OpenOptions));
        return UniqueHandle{handle};
    }
}    // namespace

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
    auto file_handle = open_existing_file(
        READ_CONTROL, m_root.get(), underlying_name.c_str(), FILE_OPEN_FOR_BACKUP_INTENT);
    if (PSecurityDescriptorSize)
    {
        // If we successfully opened the file, query its security descriptor
        DWORD sd_size = 0;
        NT_CHECK_CALL(NtQuerySecurityObject(file_handle.get(),
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
            file_handle.get(),
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
    CreateOptions &= FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE;
    auto underlying_name = translate_name(FileName);
    auto file_handle = open_existing_file(GrantedAccess,
                                          m_root.get(),
                                          underlying_name.c_str(),
                                          FILE_OPEN_FOR_BACKUP_INTENT | CreateOptions);
    auto under_info = read_file_info_from_handle(file_handle.get());

    std::unique_ptr<LiteNTBase> lite_nt_base;
    if (under_info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
    }
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
