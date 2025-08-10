#include "nt_stream.h"
#include "myutils.h"
#include "nt_exception.h"
#include "ntdecls.h"

namespace securefs
{
length_type NTStream::read(void* output, offset_type offset, length_type length)
{
    if (length == 0)
        return 0;

    IO_STATUS_BLOCK io_status_block;
    LARGE_INTEGER li_offset;
    li_offset.QuadPart = offset;

    NTSTATUS st = NtReadFile(m_handle.get(),
                             nullptr,
                             nullptr,
                             nullptr,
                             &io_status_block,
                             output,
                             length,
                             &li_offset,
                             nullptr);

    if (st == STATUS_END_OF_FILE)
    {
        return 0;
    }
    if (!NT_SUCCESS(st))
    {
        throw NTException(st, "NtReadFile");
    }
    return io_status_block.Information;
}

void NTStream::write(const void* input, offset_type offset, length_type length)
{
    if (length == 0)
        return;

    IO_STATUS_BLOCK io_status_block;
    LARGE_INTEGER li_offset;
    li_offset.QuadPart = offset;

    NTSTATUS st = NtWriteFile(m_handle.get(),
                              nullptr,
                              nullptr,
                              nullptr,
                              &io_status_block,
                              const_cast<void*>(input),
                              length,
                              &li_offset,
                              nullptr);

    if (!NT_SUCCESS(st))
    {
        throw NTException(st, "NtWriteFile");
    }

    if (io_status_block.Information != length)
        throw_runtime_error("Partial write");
}

length_type NTStream::size() const
{
    IO_STATUS_BLOCK io_status_block;
    FILE_STANDARD_INFORMATION info;
    NTSTATUS st = NtQueryInformationFile(
        m_handle.get(),
        &io_status_block,
        &info,
        sizeof(info),
        static_cast<FILE_INFORMATION_CLASS>(5) /*FileStandardInformation*/);
    if (!NT_SUCCESS(st))
        throw NTException(st, "NtQueryInformationFile");
    return info.EndOfFile.QuadPart;
}

void NTStream::flush()
{
    IO_STATUS_BLOCK io_status_block;
    NTSTATUS st = NtFlushBuffersFile(m_handle.get(), &io_status_block);
    if (!NT_SUCCESS(st))
        throw NTException(st, "NtFlushBuffersFile");
}

void NTStream::resize(length_type len)
{
    IO_STATUS_BLOCK io_status_block;
    FILE_END_OF_FILE_INFORMATION info;
    info.EndOfFile.QuadPart = len;

    NTSTATUS st = NtSetInformationFile(
        m_handle.get(),
        &io_status_block,
        &info,
        sizeof(info),
        static_cast<FILE_INFORMATION_CLASS>(20) /*FileEndOfFileInformation*/);
    if (!NT_SUCCESS(st))
        throw NTException(st, "NtSetInformationFile");
}

bool NTStream::is_sparse() const noexcept { return true; }
}    // namespace securefs
