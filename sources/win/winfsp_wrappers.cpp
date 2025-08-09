#include "winfsp_wrappers.h"

#include "exceptions.h"
#include "logger.h"
#include "nt_exception.h"

#include <exception>

namespace securefs
{
static inline WinFspFileSystem* to_obj(FSP_FILE_SYSTEM* FileSystem)
{
    return reinterpret_cast<WinFspFileSystem*>(FileSystem->UserContext);
}

static NTSTATUS read_status_from_exception(const std::exception& e)
{
    if (auto* p = dynamic_cast<const NTException*>(&e); p)
    {
        return p->status();
    }
    if (auto* p = dynamic_cast<const ExceptionBase*>(&e); p)
    {
        return errno_to_ntstatus(p->error_number());
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WINAPI WinFspFileSystem::static_GetVolumeInfo(FSP_FILE_SYSTEM* FileSystem,
                                                       FSP_FSCTL_VOLUME_INFO* VolumeInfo)
{
    if (!to_obj(FileSystem)->has_GetVolumeInfo())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vGetVolumeInfo(VolumeInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling GetVolumeInfo (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_SetVolumeLabel(FSP_FILE_SYSTEM* FileSystem,
                                                        PWSTR VolumeLabel,
                                                        FSP_FSCTL_VOLUME_INFO* VolumeInfo)
{
    if (!to_obj(FileSystem)->has_SetVolumeLabel())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vSetVolumeLabel(VolumeLabel, VolumeInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling SetVolumeLabel (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_GetSecurityByName(FSP_FILE_SYSTEM* FileSystem,
                                                           PWSTR FileName,
                                                           PUINT32 PFileAttributes,
                                                           PSECURITY_DESCRIPTOR SecurityDescriptor,
                                                           SIZE_T* PSecurityDescriptorSize)
{
    if (!to_obj(FileSystem)->has_GetSecurityByName())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vGetSecurityByName(
                FileName, PFileAttributes, SecurityDescriptor, PSecurityDescriptorSize);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling GetSecurityByName (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_Create(FSP_FILE_SYSTEM* FileSystem,
                                                PWSTR FileName,
                                                UINT32 CreateOptions,
                                                UINT32 GrantedAccess,
                                                UINT32 FileAttributes,
                                                PSECURITY_DESCRIPTOR SecurityDescriptor,
                                                UINT64 AllocationSize,
                                                PVOID* PFileContext,
                                                FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_Create())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vCreate(FileName,
                      CreateOptions,
                      GrantedAccess,
                      FileAttributes,
                      SecurityDescriptor,
                      AllocationSize,
                      PFileContext,
                      FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling Create (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_Open(FSP_FILE_SYSTEM* FileSystem,
                                              PWSTR FileName,
                                              UINT32 CreateOptions,
                                              UINT32 GrantedAccess,
                                              PVOID* PFileContext,
                                              FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_Open())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vOpen(FileName, CreateOptions, GrantedAccess, PFileContext, FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling Open (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_Overwrite(FSP_FILE_SYSTEM* FileSystem,
                                                   PVOID FileContext,
                                                   UINT32 FileAttributes,
                                                   BOOLEAN ReplaceFileAttributes,
                                                   UINT64 AllocationSize,
                                                   FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_Overwrite())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vOverwrite(
                FileContext, FileAttributes, ReplaceFileAttributes, AllocationSize, FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling Overwrite (status 0x%X): %s", status, e.what());
        return status;
    }
}

VOID WINAPI WinFspFileSystem::static_Cleanup(FSP_FILE_SYSTEM* FileSystem,
                                             PVOID FileContext,
                                             PWSTR FileName,
                                             ULONG Flags)
{
    if (!to_obj(FileSystem)->has_Cleanup())
        return;
    try
    {
        to_obj(FileSystem)->vCleanup(FileContext, FileName, Flags);
    }
    catch (const std::exception& e)
    {
        ERROR_LOG("Error calling Cleanup: %s", e.what());
    }
}

VOID WINAPI WinFspFileSystem::static_Close(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext)
{
    if (!to_obj(FileSystem)->has_Close())
        return;
    try
    {
        to_obj(FileSystem)->vClose(FileContext);
    }
    catch (const std::exception& e)
    {
        ERROR_LOG("Error calling Close: %s", e.what());
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_Read(FSP_FILE_SYSTEM* FileSystem,
                                              PVOID FileContext,
                                              PVOID Buffer,
                                              UINT64 Offset,
                                              ULONG Length,
                                              PULONG PBytesTransferred)
{
    if (!to_obj(FileSystem)->has_Read())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vRead(FileContext, Buffer, Offset, Length, PBytesTransferred);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling Read (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_Write(FSP_FILE_SYSTEM* FileSystem,
                                               PVOID FileContext,
                                               PVOID Buffer,
                                               UINT64 Offset,
                                               ULONG Length,
                                               BOOLEAN WriteToEndOfFile,
                                               BOOLEAN ConstrainedIo,
                                               PULONG PBytesTransferred,
                                               FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_Write())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vWrite(FileContext,
                     Buffer,
                     Offset,
                     Length,
                     WriteToEndOfFile,
                     ConstrainedIo,
                     PBytesTransferred,
                     FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling Write (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_Flush(FSP_FILE_SYSTEM* FileSystem,
                                               PVOID FileContext,
                                               FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_Flush())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vFlush(FileContext, FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling Flush (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_GetFileInfo(FSP_FILE_SYSTEM* FileSystem,
                                                     PVOID FileContext,
                                                     FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_GetFileInfo())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vGetFileInfo(FileContext, FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling GetFileInfo (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_SetBasicInfo(FSP_FILE_SYSTEM* FileSystem,
                                                      PVOID FileContext,
                                                      UINT32 FileAttributes,
                                                      UINT64 CreationTime,
                                                      UINT64 LastAccessTime,
                                                      UINT64 LastWriteTime,
                                                      UINT64 ChangeTime,
                                                      FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_SetBasicInfo())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vSetBasicInfo(FileContext,
                            FileAttributes,
                            CreationTime,
                            LastAccessTime,
                            LastWriteTime,
                            ChangeTime,
                            FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling SetBasicInfo (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_SetFileSize(FSP_FILE_SYSTEM* FileSystem,
                                                     PVOID FileContext,
                                                     UINT64 NewSize,
                                                     BOOLEAN SetAllocationSize,
                                                     FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_SetFileSize())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vSetFileSize(FileContext, NewSize, SetAllocationSize, FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling SetFileSize (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_CanDelete(FSP_FILE_SYSTEM* FileSystem,
                                                   PVOID FileContext,
                                                   PWSTR FileName)
{
    if (!to_obj(FileSystem)->has_CanDelete())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vCanDelete(FileContext, FileName);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling CanDelete (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_Rename(FSP_FILE_SYSTEM* FileSystem,
                                                PVOID FileContext,
                                                PWSTR FileName,
                                                PWSTR NewFileName,
                                                BOOLEAN ReplaceIfExists)
{
    if (!to_obj(FileSystem)->has_Rename())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vRename(FileContext, FileName, NewFileName, ReplaceIfExists);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling Rename (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_GetSecurity(FSP_FILE_SYSTEM* FileSystem,
                                                     PVOID FileContext,
                                                     PSECURITY_DESCRIPTOR SecurityDescriptor,
                                                     SIZE_T* PSecurityDescriptorSize)
{
    if (!to_obj(FileSystem)->has_GetSecurity())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vGetSecurity(FileContext, SecurityDescriptor, PSecurityDescriptorSize);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling GetSecurity (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_SetSecurity(FSP_FILE_SYSTEM* FileSystem,
                                                     PVOID FileContext,
                                                     SECURITY_INFORMATION SecurityInformation,
                                                     PSECURITY_DESCRIPTOR ModificationDescriptor)
{
    if (!to_obj(FileSystem)->has_SetSecurity())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vSetSecurity(FileContext, SecurityInformation, ModificationDescriptor);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling SetSecurity (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_ReadDirectory(FSP_FILE_SYSTEM* FileSystem,
                                                       PVOID FileContext,
                                                       PWSTR Pattern,
                                                       PWSTR Marker,
                                                       PVOID Buffer,
                                                       ULONG Length,
                                                       PULONG PBytesTransferred)
{
    if (!to_obj(FileSystem)->has_ReadDirectory())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vReadDirectory(FileContext, Pattern, Marker, Buffer, Length, PBytesTransferred);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling ReadDirectory (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_GetEa(FSP_FILE_SYSTEM* FileSystem,
                                               PVOID FileContext,
                                               PFILE_FULL_EA_INFORMATION Buffer,
                                               ULONG Length,
                                               PULONG PBytesTransferred)
{
    if (!to_obj(FileSystem)->has_GetEa())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vGetEa(FileContext, Buffer, Length, PBytesTransferred);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling GetEa (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_SetEa(FSP_FILE_SYSTEM* FileSystem,
                                               PVOID FileContext,
                                               PFILE_FULL_EA_INFORMATION Ea,
                                               ULONG Length,
                                               FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_SetEa())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vSetEa(FileContext, Ea, Length, FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling SetEa (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_GetStreamInfo(FSP_FILE_SYSTEM* FileSystem,
                                                       PVOID FileContext,
                                                       PVOID Buffer,
                                                       ULONG Length,
                                                       PULONG PBytesTransferred)
{
    if (!to_obj(FileSystem)->has_GetStreamInfo())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vGetStreamInfo(FileContext, Buffer, Length, PBytesTransferred);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling GetStreamInfo (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_SetStreamInfo(FSP_FILE_SYSTEM* FileSystem,
                                                       PVOID FileContext,
                                                       PVOID Buffer,
                                                       ULONG Length)
{
    if (!to_obj(FileSystem)->has_SetStreamInfo())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vSetStreamInfo(FileContext, Buffer, Length);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling SetStreamInfo (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_GetReparsePoint(FSP_FILE_SYSTEM* FileSystem,
                                                         PVOID FileContext,
                                                         PVOID Buffer,
                                                         PULONG PSize)
{
    if (!to_obj(FileSystem)->has_GetReparsePoint())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vGetReparsePoint(FileContext, Buffer, PSize);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling GetReparsePoint (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_SetReparsePoint(FSP_FILE_SYSTEM* FileSystem,
                                                         PVOID FileContext,
                                                         PVOID Buffer,
                                                         ULONG Size,
                                                         FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_SetReparsePoint())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vSetReparsePoint(FileContext, Buffer, Size, FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling SetReparsePoint (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_DeleteReparsePoint(FSP_FILE_SYSTEM* FileSystem,
                                                            PVOID FileContext,
                                                            PVOID Buffer,
                                                            ULONG Size,
                                                            FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_DeleteReparsePoint())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vDeleteReparsePoint(FileContext, Buffer, Size, FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling DeleteReparsePoint (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_SwitchToAlternateStream(FSP_FILE_SYSTEM* FileSystem,
                                                                 PVOID* PFileContext,
                                                                 PWSTR StreamName,
                                                                 PVOID* PStreamContext)
{
    if (!to_obj(FileSystem)->has_SwitchToAlternateStream())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vSwitchToAlternateStream(PFileContext, StreamName, PStreamContext);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling SwitchToAlternateStream (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_Suspend(FSP_FILE_SYSTEM* FileSystem, ULONG Flags)
{
    if (!to_obj(FileSystem)->has_Suspend())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vSuspend(Flags);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling Suspend (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_Resume(FSP_FILE_SYSTEM* FileSystem, ULONG Flags)
{
    if (!to_obj(FileSystem)->has_Resume())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vResume(Flags);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling Resume (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_GetDirInfoByName(FSP_FILE_SYSTEM* FileSystem,
                                                          PVOID FileContext,
                                                          PWSTR FileName,
                                                          FSP_FSCTL_DIR_INFO* DirInfo)
{
    if (!to_obj(FileSystem)->has_GetDirInfoByName())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vGetDirInfoByName(FileContext, FileName, DirInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling GetDirInfoByName (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_Control(FSP_FILE_SYSTEM* FileSystem,
                                                 PVOID FileContext,
                                                 UINT32 ControlCode,
                                                 PVOID InputBuffer,
                                                 ULONG InputBufferLength,
                                                 PVOID OutputBuffer,
                                                 ULONG OutputBufferLength,
                                                 PULONG PBytesTransferred)
{
    if (!to_obj(FileSystem)->has_Control())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vControl(FileContext,
                       ControlCode,
                       InputBuffer,
                       InputBufferLength,
                       OutputBuffer,
                       OutputBufferLength,
                       PBytesTransferred);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling Control (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_SetDelete(FSP_FILE_SYSTEM* FileSystem,
                                                   PVOID FileContext,
                                                   PWSTR FileName,
                                                   BOOLEAN DeleteFile)
{
    if (!to_obj(FileSystem)->has_SetDelete())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)->vSetDelete(FileContext, FileName, DeleteFile);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling SetDelete (status 0x%X): %s", status, e.what());
        return status;
    }
}

NTSTATUS WINAPI WinFspFileSystem::static_OverwriteEx(FSP_FILE_SYSTEM* FileSystem,
                                                     PVOID FileContext,
                                                     UINT32 FileAttributes,
                                                     BOOLEAN ReplaceFileAttributes,
                                                     UINT64 AllocationSize,
                                                     PFILE_FULL_EA_INFORMATION Ea,
                                                     ULONG EaLength,
                                                     FSP_FSCTL_FILE_INFO* FileInfo)
{
    if (!to_obj(FileSystem)->has_OverwriteEx())
        return STATUS_NOT_IMPLEMENTED;
    try
    {
        return to_obj(FileSystem)
            ->vOverwriteEx(FileContext,
                           FileAttributes,
                           ReplaceFileAttributes,
                           AllocationSize,
                           Ea,
                           EaLength,
                           FileInfo);
    }
    catch (const std::exception& e)
    {
        NTSTATUS status = read_status_from_exception(e);
        ERROR_LOG("Error calling OverwriteEx (status 0x%X): %s", status, e.what());
        return status;
    }
}

VOID WINAPI WinFspFileSystem::static_DispatcherStopped(FSP_FILE_SYSTEM* FileSystem,
                                                       BOOLEAN Normally)
{
    if (!to_obj(FileSystem)->has_DispatcherStopped())
        return;
    try
    {
        to_obj(FileSystem)->vDispatcherStopped(Normally);
    }
    catch (const std::exception& e)
    {
        ERROR_LOG("Error calling DispatcherStopped: %s", e.what());
    }
}

FSP_FILE_SYSTEM_INTERFACE WinFspFileSystem::as_fsp_interface() const
{
    FSP_FILE_SYSTEM_INTERFACE fsp_iface;
    memset(&fsp_iface, 0, sizeof(fsp_iface));

    if (has_GetVolumeInfo())
        fsp_iface.GetVolumeInfo = static_GetVolumeInfo;
    if (has_SetVolumeLabel())
        fsp_iface.SetVolumeLabel = static_SetVolumeLabel;
    if (has_GetSecurityByName())
        fsp_iface.GetSecurityByName = static_GetSecurityByName;
    if (has_Create())
        fsp_iface.Create = static_Create;
    if (has_Open())
        fsp_iface.Open = static_Open;
    if (has_Overwrite())
        fsp_iface.Overwrite = static_Overwrite;
    if (has_Cleanup())
        fsp_iface.Cleanup = static_Cleanup;
    if (has_Close())
        fsp_iface.Close = static_Close;
    if (has_Read())
        fsp_iface.Read = static_Read;
    if (has_Write())
        fsp_iface.Write = static_Write;
    if (has_Flush())
        fsp_iface.Flush = static_Flush;
    if (has_GetFileInfo())
        fsp_iface.GetFileInfo = static_GetFileInfo;
    if (has_SetBasicInfo())
        fsp_iface.SetBasicInfo = static_SetBasicInfo;
    if (has_SetFileSize())
        fsp_iface.SetFileSize = static_SetFileSize;
    if (has_CanDelete())
        fsp_iface.CanDelete = static_CanDelete;
    if (has_Rename())
        fsp_iface.Rename = static_Rename;
    if (has_GetSecurity())
        fsp_iface.GetSecurity = static_GetSecurity;
    if (has_SetSecurity())
        fsp_iface.SetSecurity = static_SetSecurity;
    if (has_ReadDirectory())
        fsp_iface.ReadDirectory = static_ReadDirectory;
    if (has_GetStreamInfo())
        fsp_iface.GetStreamInfo = static_GetStreamInfo;
    if (has_GetDirInfoByName())
        fsp_iface.GetDirInfoByName = static_GetDirInfoByName;
    if (has_Control())
        fsp_iface.Control = static_Control;
    if (has_SetDelete())
        fsp_iface.SetDelete = static_SetDelete;
    if (has_OverwriteEx())
        fsp_iface.OverwriteEx = static_OverwriteEx;
    if (has_GetEa())
        fsp_iface.GetEa = static_GetEa;
    if (has_SetEa())
        fsp_iface.SetEa = static_SetEa;
    if (has_DispatcherStopped())
        fsp_iface.DispatcherStopped = static_DispatcherStopped;

    return fsp_iface;
}
}    // namespace securefs
