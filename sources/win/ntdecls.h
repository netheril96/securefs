#pragma once

#include <winfsp/winfsp.h>

extern "C"
{
    typedef struct
    {
        ACCESS_MASK AccessFlags;
    } FILE_ACCESS_INFORMATION;
    typedef struct
    {
        ULONG AlignmentRequirement;
    } FILE_ALIGNMENT_INFORMATION;
    typedef struct
    {
        LARGE_INTEGER AllocationSize;
    } FILE_ALLOCATION_INFORMATION;
    typedef struct
    {
        ULONG FileAttributes;
        ULONG ReparseTag;
    } FILE_ATTRIBUTE_TAG_INFORMATION;
    typedef struct
    {
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        ULONG FileAttributes;
    } FILE_BASIC_INFORMATION;
    typedef struct
    {
        BOOLEAN DeleteFile;
    } FILE_DISPOSITION_INFORMATION;
    typedef struct
    {
        ULONG Flags;
    } FILE_DISPOSITION_INFORMATION_EX;
    typedef struct
    {
        ULONG EaSize;
    } FILE_EA_INFORMATION;
    typedef struct
    {
        LARGE_INTEGER EndOfFile;
    } FILE_END_OF_FILE_INFORMATION;
    typedef struct
    {
        LARGE_INTEGER IndexNumber;
    } FILE_INTERNAL_INFORMATION;
    typedef struct
    {
        ULONG Mode;
    } FILE_MODE_INFORMATION;
    typedef struct
    {
        ULONG FileNameLength;
        WCHAR FileName[1];
    } FILE_NAME_INFORMATION;
    typedef struct
    {
        LARGE_INTEGER CurrentByteOffset;
    } FILE_POSITION_INFORMATION;
    typedef struct
    {
        union
        {
            BOOLEAN ReplaceIfExists;
            ULONG Flags;
        } DUMMYUNIONNAME;
        HANDLE RootDirectory;
        ULONG FileNameLength;
        WCHAR FileName[1];
    } FILE_RENAME_INFORMATION;
    typedef struct
    {
        LARGE_INTEGER AllocationSize;
        LARGE_INTEGER EndOfFile;
        ULONG NumberOfLinks;
        BOOLEAN DeletePending;
        BOOLEAN Directory;
    } FILE_STANDARD_INFORMATION;
    typedef struct
    {
        ULONG NextEntryOffset;
        ULONG StreamNameLength;
        LARGE_INTEGER StreamSize;
        LARGE_INTEGER StreamAllocationSize;
        WCHAR StreamName[1];
    } FILE_STREAM_INFORMATION;
    typedef struct
    {
        FILE_BASIC_INFORMATION BasicInformation;
        FILE_STANDARD_INFORMATION StandardInformation;
        FILE_INTERNAL_INFORMATION InternalInformation;
        FILE_EA_INFORMATION EaInformation;
        FILE_ACCESS_INFORMATION AccessInformation;
        FILE_POSITION_INFORMATION PositionInformation;
        FILE_MODE_INFORMATION ModeInformation;
        FILE_ALIGNMENT_INFORMATION AlignmentInformation;
        FILE_NAME_INFORMATION NameInformation;
    } FILE_ALL_INFORMATION;

    typedef struct
    {
        ULONG NextEntryOffset;
        ULONG FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG FileAttributes;
        ULONG FileNameLength;
        ULONG EaSize;
        CCHAR ShortNameLength;
        WCHAR ShortName[12];
        LARGE_INTEGER FileId;
        WCHAR FileName[1];
    } FILE_ID_BOTH_DIR_INFORMATION;

    typedef struct
    {
        ULONG FileSystemAttributes;
        LONG MaximumComponentNameLength;
        ULONG FileSystemNameLength;
        WCHAR FileSystemName[1];
    } FILE_FS_ATTRIBUTE_INFORMATION;
    typedef struct
    {
        LARGE_INTEGER TotalAllocationUnits;
        LARGE_INTEGER AvailableAllocationUnits;
        ULONG SectorsPerAllocationUnit;
        ULONG BytesPerSector;
    } FILE_FS_SIZE_INFORMATION;

    NTSTATUS NTAPI NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);

    NTSTATUS NTAPI NtFsControlFile(HANDLE FileHandle,
                                   HANDLE Event,
                                   PIO_APC_ROUTINE ApcRoutine,
                                   PVOID ApcContext,
                                   PIO_STATUS_BLOCK IoStatusBlock,
                                   ULONG FsControlCode,
                                   PVOID InputBuffer,
                                   ULONG InputBufferLength,
                                   PVOID OutputBuffer,
                                   ULONG OutputBufferLength);

    NTSTATUS NTAPI NtQueryEaFile(HANDLE FileHandle,
                                 PIO_STATUS_BLOCK IoStatusBlock,
                                 PVOID Buffer,
                                 ULONG Length,
                                 BOOLEAN ReturnSingleEntry,
                                 PVOID EaList,
                                 ULONG EaListLength,
                                 PULONG EaIndex,
                                 BOOLEAN RestartScan);

    NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE FileHandle,
                                        HANDLE Event,
                                        PIO_APC_ROUTINE ApcRoutine,
                                        PVOID ApcContext,
                                        PIO_STATUS_BLOCK IoStatusBlock,
                                        PVOID FileInformation,
                                        ULONG Length,
                                        FILE_INFORMATION_CLASS FileInformationClass,
                                        BOOLEAN ReturnSingleEntry,
                                        PUNICODE_STRING FileName,
                                        BOOLEAN RestartScan);

    NTSTATUS NTAPI NtQueryInformationFile(HANDLE FileHandle,
                                          PIO_STATUS_BLOCK IoStatusBlock,
                                          PVOID FileInformation,
                                          ULONG Length,
                                          FILE_INFORMATION_CLASS FileInformationClass);

    NTSTATUS NTAPI NtQuerySecurityObject(HANDLE Handle,
                                         SECURITY_INFORMATION SecurityInformation,
                                         PSECURITY_DESCRIPTOR SecurityDescriptor,
                                         ULONG Length,
                                         PULONG LengthNeeded);

    NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE FileHandle,
                                                PIO_STATUS_BLOCK IoStatusBlock,
                                                PVOID FsInformation,
                                                ULONG Length,
                                                ULONG FsInformationClass);

    NTSTATUS NTAPI NtReadFile(HANDLE FileHandle,
                              HANDLE Event,
                              PIO_APC_ROUTINE ApcRoutine,
                              PVOID ApcContext,
                              PIO_STATUS_BLOCK IoStatusBlock,
                              PVOID Buffer,
                              ULONG Length,
                              PLARGE_INTEGER ByteOffset,
                              PULONG Key);

    NTSTATUS NTAPI NtSetEaFile(HANDLE FileHandle,
                               PIO_STATUS_BLOCK IoStatusBlock,
                               PVOID Buffer,
                               ULONG Length);

    NTSTATUS NTAPI NtSetInformationFile(HANDLE FileHandle,
                                        PIO_STATUS_BLOCK IoStatusBlock,
                                        PVOID FileInformation,
                                        ULONG Length,
                                        FILE_INFORMATION_CLASS FileInformationClass);

    NTSTATUS NTAPI NtSetSecurityObject(HANDLE Handle,
                                       SECURITY_INFORMATION SecurityInformation,
                                       PSECURITY_DESCRIPTOR SecurityDescriptor);

    NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle,
                               HANDLE Event,
                               PIO_APC_ROUTINE ApcRoutine,
                               PVOID ApcContext,
                               PIO_STATUS_BLOCK IoStatusBlock,
                               PVOID Buffer,
                               ULONG Length,
                               PLARGE_INTEGER ByteOffset,
                               PULONG Key);

    NTSTATUS NTAPI NtLockFile(HANDLE FileHandle,
                              HANDLE Event,
                              PIO_APC_ROUTINE ApcRoutine,
                              PVOID ApcContext,
                              PIO_STATUS_BLOCK IoStatusBlock,
                              PLARGE_INTEGER ByteOffset,
                              PLARGE_INTEGER Length,
                              ULONG Key,
                              BOOLEAN FailImmediately,
                              BOOLEAN ExclusiveLock);

    NTSTATUS NTAPI NtUnlockFile(HANDLE FileHandle,
                                PIO_STATUS_BLOCK IoStatusBlock,
                                PLARGE_INTEGER ByteOffset,
                                PLARGE_INTEGER Length,
                                ULONG Key);
}
