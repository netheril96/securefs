#pragma once

#include "object.h"

#include <memory>

#include <winfsp/winfsp.h>

namespace securefs
{
class WinFspFileSystem : public Object
{
public:
    virtual const FSP_FSCTL_VOLUME_PARAMS& GetVolumeParams() const = 0;
    void start();
    void stop();

    FSP_FILE_SYSTEM_INTERFACE as_fsp_interface() const;
    virtual NTSTATUS vGetVolumeInfo(FSP_FSCTL_VOLUME_INFO* VolumeInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_GetVolumeInfo() const { return false; }

    virtual NTSTATUS vSetVolumeLabel(PWSTR VolumeLabel, FSP_FSCTL_VOLUME_INFO* VolumeInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_SetVolumeLabel() const { return false; }

    virtual NTSTATUS vGetSecurityByName(PWSTR FileName,
                                        PUINT32 PFileAttributes,
                                        PSECURITY_DESCRIPTOR SecurityDescriptor,
                                        SIZE_T* PSecurityDescriptorSize)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_GetSecurityByName() const { return false; }

    virtual NTSTATUS vCreate(PWSTR FileName,
                             UINT32 CreateOptions,
                             UINT32 GrantedAccess,
                             UINT32 FileAttributes,
                             PSECURITY_DESCRIPTOR SecurityDescriptor,
                             UINT64 AllocationSize,
                             PVOID* PFileContext,
                             FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_Create() const { return false; }

    virtual NTSTATUS vOpen(PWSTR FileName,
                           UINT32 CreateOptions,
                           UINT32 GrantedAccess,
                           PVOID* PFileContext,
                           FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_Open() const { return false; }

    virtual NTSTATUS vOverwrite(PVOID FileContext,
                                UINT32 FileAttributes,
                                BOOLEAN ReplaceFileAttributes,
                                UINT64 AllocationSize,
                                FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_Overwrite() const { return false; }

    virtual VOID vCleanup(PVOID FileContext, PWSTR FileName, ULONG Flags) {}
    virtual bool has_Cleanup() const { return false; }

    virtual VOID vClose(PVOID FileContext) {}
    virtual bool has_Close() const { return false; }

    virtual NTSTATUS
    vRead(PVOID FileContext, PVOID Buffer, UINT64 Offset, ULONG Length, PULONG PBytesTransferred)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_Read() const { return false; }

    virtual NTSTATUS vWrite(PVOID FileContext,
                            PVOID Buffer,
                            UINT64 Offset,
                            ULONG Length,
                            BOOLEAN WriteToEndOfFile,
                            BOOLEAN ConstrainedIo,
                            PULONG PBytesTransferred,
                            FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_Write() const { return false; }

    virtual NTSTATUS vFlush(PVOID FileContext, FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_Flush() const { return false; }

    virtual NTSTATUS vGetFileInfo(PVOID FileContext, FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_GetFileInfo() const { return false; }

    virtual NTSTATUS vSetBasicInfo(PVOID FileContext,
                                   UINT32 FileAttributes,
                                   UINT64 CreationTime,
                                   UINT64 LastAccessTime,
                                   UINT64 LastWriteTime,
                                   UINT64 ChangeTime,
                                   FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_SetBasicInfo() const { return false; }

    virtual NTSTATUS vSetFileSize(PVOID FileContext,
                                  UINT64 NewSize,
                                  BOOLEAN SetAllocationSize,
                                  FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_SetFileSize() const { return false; }

    virtual NTSTATUS vCanDelete(PVOID FileContext, PWSTR FileName)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_CanDelete() const { return false; }

    virtual NTSTATUS
    vRename(PVOID FileContext, PWSTR FileName, PWSTR NewFileName, BOOLEAN ReplaceIfExists)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_Rename() const { return false; }

    virtual NTSTATUS vGetSecurity(PVOID FileContext,
                                  PSECURITY_DESCRIPTOR SecurityDescriptor,
                                  SIZE_T* PSecurityDescriptorSize)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_GetSecurity() const { return false; }

    virtual NTSTATUS vSetSecurity(PVOID FileContext,
                                  SECURITY_INFORMATION SecurityInformation,
                                  PSECURITY_DESCRIPTOR ModificationDescriptor)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_SetSecurity() const { return false; }

    virtual NTSTATUS vReadDirectory(PVOID FileContext,
                                    PWSTR Pattern,
                                    PWSTR Marker,
                                    PVOID Buffer,
                                    ULONG Length,
                                    PULONG PBytesTransferred)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_ReadDirectory() const { return false; }

    virtual NTSTATUS
    vGetEa(PVOID FileContext, PFILE_FULL_EA_INFORMATION Ea, ULONG Length, PULONG PBytesTransferred)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_GetEa() const { return false; }

    virtual NTSTATUS vSetEa(PVOID FileContext,
                            PFILE_FULL_EA_INFORMATION Ea,
                            ULONG Length,
                            FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_SetEa() const { return false; }

    virtual NTSTATUS
    vGetStreamInfo(PVOID FileContext, PVOID Buffer, ULONG Length, PULONG PBytesTransferred)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_GetStreamInfo() const { return false; }

    virtual NTSTATUS vSetStreamInfo(PVOID FileContext, PVOID Buffer, ULONG Length)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_SetStreamInfo() const { return false; }

    virtual NTSTATUS vGetReparsePoint(PVOID FileContext, PVOID Buffer, PULONG PSize)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_GetReparsePoint() const { return false; }

    virtual NTSTATUS
    vSetReparsePoint(PVOID FileContext, PVOID Buffer, ULONG Size, FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_SetReparsePoint() const { return false; }

    virtual NTSTATUS
    vDeleteReparsePoint(PVOID FileContext, PVOID Buffer, ULONG Size, FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_DeleteReparsePoint() const { return false; }

    virtual NTSTATUS
    vSwitchToAlternateStream(PVOID* PFileContext, PWSTR StreamName, PVOID* PStreamContext)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_SwitchToAlternateStream() const { return false; }

    virtual NTSTATUS vSuspend(ULONG Flags) { return STATUS_NOT_IMPLEMENTED; }
    virtual bool has_Suspend() const { return false; }

    virtual NTSTATUS vResume(ULONG Flags) { return STATUS_NOT_IMPLEMENTED; }
    virtual bool has_Resume() const { return false; }

    virtual NTSTATUS
    vGetDirInfoByName(PVOID FileContext, PWSTR FileName, FSP_FSCTL_DIR_INFO* DirInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_GetDirInfoByName() const { return false; }

    virtual NTSTATUS vControl(PVOID FileContext,
                              UINT32 ControlCode,
                              PVOID InputBuffer,
                              ULONG InputBufferLength,
                              PVOID OutputBuffer,
                              ULONG OutputBufferLength,
                              PULONG PBytesTransferred)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_Control() const { return false; }

    virtual NTSTATUS vSetDelete(PVOID FileContext, PWSTR FileName, BOOLEAN DeleteFile)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_SetDelete() const { return false; }

    virtual NTSTATUS vOverwriteEx(PVOID FileContext,
                                  UINT32 FileAttributes,
                                  BOOLEAN ReplaceFileAttributes,
                                  UINT64 AllocationSize,
                                  PFILE_FULL_EA_INFORMATION Ea,
                                  ULONG EaLength,
                                  FSP_FSCTL_FILE_INFO* FileInfo)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    virtual bool has_OverwriteEx() const { return false; }

    virtual VOID vDispatcherStopped(BOOLEAN Normally) {}
    virtual bool has_DispatcherStopped() const { return false; }

private:
    static NTSTATUS WINAPI static_GetVolumeInfo(FSP_FILE_SYSTEM* FileSystem,
                                                FSP_FSCTL_VOLUME_INFO* VolumeInfo);

    static NTSTATUS WINAPI static_SetVolumeLabel(FSP_FILE_SYSTEM* FileSystem,
                                                 PWSTR VolumeLabel,
                                                 FSP_FSCTL_VOLUME_INFO* VolumeInfo);

    static NTSTATUS WINAPI static_GetSecurityByName(FSP_FILE_SYSTEM* FileSystem,
                                                    PWSTR FileName,
                                                    PUINT32 PFileAttributes,
                                                    PSECURITY_DESCRIPTOR SecurityDescriptor,
                                                    SIZE_T* PSecurityDescriptorSize);

    static NTSTATUS WINAPI static_Create(FSP_FILE_SYSTEM* FileSystem,
                                         PWSTR FileName,
                                         UINT32 CreateOptions,
                                         UINT32 GrantedAccess,
                                         UINT32 FileAttributes,
                                         PSECURITY_DESCRIPTOR SecurityDescriptor,
                                         UINT64 AllocationSize,
                                         PVOID* PFileContext,
                                         FSP_FSCTL_FILE_INFO* FileInfo);

    static NTSTATUS WINAPI static_Open(FSP_FILE_SYSTEM* FileSystem,
                                       PWSTR FileName,
                                       UINT32 CreateOptions,
                                       UINT32 GrantedAccess,
                                       PVOID* PFileContext,
                                       FSP_FSCTL_FILE_INFO* FileInfo);

    static NTSTATUS WINAPI static_Overwrite(FSP_FILE_SYSTEM* FileSystem,
                                            PVOID FileContext,
                                            UINT32 FileAttributes,
                                            BOOLEAN ReplaceFileAttributes,
                                            UINT64 AllocationSize,
                                            FSP_FSCTL_FILE_INFO* FileInfo);

    static VOID WINAPI static_Cleanup(FSP_FILE_SYSTEM* FileSystem,
                                      PVOID FileContext,
                                      PWSTR FileName,
                                      ULONG Flags);

    static VOID WINAPI static_Close(FSP_FILE_SYSTEM* FileSystem, PVOID FileContext);

    static NTSTATUS WINAPI static_Read(FSP_FILE_SYSTEM* FileSystem,
                                       PVOID FileContext,
                                       PVOID Buffer,
                                       UINT64 Offset,
                                       ULONG Length,
                                       PULONG PBytesTransferred);

    static NTSTATUS WINAPI static_Write(FSP_FILE_SYSTEM* FileSystem,
                                        PVOID FileContext,
                                        PVOID Buffer,
                                        UINT64 Offset,
                                        ULONG Length,
                                        BOOLEAN WriteToEndOfFile,
                                        BOOLEAN ConstrainedIo,
                                        PULONG PBytesTransferred,
                                        FSP_FSCTL_FILE_INFO* FileInfo);

    static NTSTATUS WINAPI static_Flush(FSP_FILE_SYSTEM* FileSystem,
                                        PVOID FileContext,
                                        FSP_FSCTL_FILE_INFO* FileInfo);

    static NTSTATUS WINAPI static_GetFileInfo(FSP_FILE_SYSTEM* FileSystem,
                                              PVOID FileContext,
                                              FSP_FSCTL_FILE_INFO* FileInfo);

    static NTSTATUS WINAPI static_SetBasicInfo(FSP_FILE_SYSTEM* FileSystem,
                                               PVOID FileContext,
                                               UINT32 FileAttributes,
                                               UINT64 CreationTime,
                                               UINT64 LastAccessTime,
                                               UINT64 LastWriteTime,
                                               UINT64 ChangeTime,
                                               FSP_FSCTL_FILE_INFO* FileInfo);

    static NTSTATUS WINAPI static_SetFileSize(FSP_FILE_SYSTEM* FileSystem,
                                              PVOID FileContext,
                                              UINT64 NewSize,
                                              BOOLEAN SetAllocationSize,
                                              FSP_FSCTL_FILE_INFO* FileInfo);

    static NTSTATUS WINAPI static_CanDelete(FSP_FILE_SYSTEM* FileSystem,
                                            PVOID FileContext,
                                            PWSTR FileName);

    static NTSTATUS WINAPI static_Rename(FSP_FILE_SYSTEM* FileSystem,
                                         PVOID FileContext,
                                         PWSTR FileName,
                                         PWSTR NewFileName,
                                         BOOLEAN ReplaceIfExists);

    static NTSTATUS WINAPI static_GetSecurity(FSP_FILE_SYSTEM* FileSystem,
                                              PVOID FileContext,
                                              PSECURITY_DESCRIPTOR SecurityDescriptor,
                                              SIZE_T* PSecurityDescriptorSize);

    static NTSTATUS WINAPI static_SetSecurity(FSP_FILE_SYSTEM* FileSystem,
                                              PVOID FileContext,
                                              SECURITY_INFORMATION SecurityInformation,
                                              PSECURITY_DESCRIPTOR ModificationDescriptor);

    static NTSTATUS WINAPI static_ReadDirectory(FSP_FILE_SYSTEM* FileSystem,
                                                PVOID FileContext,
                                                PWSTR Pattern,
                                                PWSTR Marker,
                                                PVOID Buffer,
                                                ULONG Length,
                                                PULONG PBytesTransferred);

    static NTSTATUS WINAPI static_GetEa(FSP_FILE_SYSTEM* FileSystem,
                                        PVOID FileContext,
                                        PFILE_FULL_EA_INFORMATION Buffer,
                                        ULONG Length,
                                        PULONG PBytesTransferred);

    static NTSTATUS WINAPI static_SetEa(FSP_FILE_SYSTEM* FileSystem,
                                        PVOID FileContext,
                                        PFILE_FULL_EA_INFORMATION Ea,
                                        ULONG Length,
                                        FSP_FSCTL_FILE_INFO* FileInfo);

    static NTSTATUS WINAPI static_GetStreamInfo(FSP_FILE_SYSTEM* FileSystem,
                                                PVOID FileContext,
                                                PVOID Buffer,
                                                ULONG Length,
                                                PULONG PBytesTransferred);

    static NTSTATUS WINAPI static_SetStreamInfo(FSP_FILE_SYSTEM* FileSystem,
                                                PVOID FileContext,
                                                PVOID Buffer,
                                                ULONG Length);

    static NTSTATUS WINAPI static_GetReparsePoint(FSP_FILE_SYSTEM* FileSystem,
                                                  PVOID FileContext,
                                                  PVOID Buffer,
                                                  PULONG PSize);

    static NTSTATUS WINAPI static_SetReparsePoint(FSP_FILE_SYSTEM* FileSystem,
                                                  PVOID FileContext,
                                                  PVOID Buffer,
                                                  ULONG Size,
                                                  FSP_FSCTL_FILE_INFO* FileInfo);

    static NTSTATUS WINAPI static_DeleteReparsePoint(FSP_FILE_SYSTEM* FileSystem,
                                                     PVOID FileContext,
                                                     PVOID Buffer,
                                                     ULONG Size,
                                                     FSP_FSCTL_FILE_INFO* FileInfo);

    static NTSTATUS WINAPI static_SwitchToAlternateStream(FSP_FILE_SYSTEM* FileSystem,
                                                          PVOID* PFileContext,
                                                          PWSTR StreamName,
                                                          PVOID* PStreamContext);

    static NTSTATUS WINAPI static_Suspend(FSP_FILE_SYSTEM* FileSystem, ULONG Flags);

    static NTSTATUS WINAPI static_Resume(FSP_FILE_SYSTEM* FileSystem, ULONG Flags);

    static NTSTATUS WINAPI static_GetDirInfoByName(FSP_FILE_SYSTEM* FileSystem,
                                                   PVOID FileContext,
                                                   PWSTR FileName,
                                                   FSP_FSCTL_DIR_INFO* DirInfo);

    static NTSTATUS WINAPI static_Control(FSP_FILE_SYSTEM* FileSystem,
                                          PVOID FileContext,
                                          UINT32 ControlCode,
                                          PVOID InputBuffer,
                                          ULONG InputBufferLength,
                                          PVOID OutputBuffer,
                                          ULONG OutputBufferLength,
                                          PULONG PBytesTransferred);

    static NTSTATUS WINAPI static_SetDelete(FSP_FILE_SYSTEM* FileSystem,
                                            PVOID FileContext,
                                            PWSTR FileName,
                                            BOOLEAN DeleteFile);

    static NTSTATUS WINAPI static_OverwriteEx(FSP_FILE_SYSTEM* FileSystem,
                                              PVOID FileContext,
                                              UINT32 FileAttributes,
                                              BOOLEAN ReplaceFileAttributes,
                                              UINT64 AllocationSize,
                                              PFILE_FULL_EA_INFORMATION Ea,
                                              ULONG EaLength,
                                              FSP_FSCTL_FILE_INFO* FileInfo);

    static VOID WINAPI static_DispatcherStopped(FSP_FILE_SYSTEM* FileSystem, BOOLEAN Normally);

private:
    struct FspFileSystemDeleter
    {
        void operator()(FSP_FILE_SYSTEM* fsp) const
        {
            if (fsp)
            {
                FspFileSystemDelete(fsp);
            }
        }
    };

    std::unique_ptr<FSP_FILE_SYSTEM, FspFileSystemDeleter> m_fileSystem;
};
}    // namespace securefs
