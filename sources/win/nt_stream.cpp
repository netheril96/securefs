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

    if (length > std::numeric_limits<ULONG>::max())
        throwInvalidArgumentException("length > ULONG_MAX");

    IO_STATUS_BLOCK io_status_block;
    LARGE_INTEGER li_offset;
    li_offset.QuadPart = offset;

    NTSTATUS st = NtReadFile(m_handle.get(),
                             nullptr,
                             nullptr,
                             nullptr,
                             &io_status_block,
                             output,
                             static_cast<ULONG>(length),
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

    if (length > std::numeric_limits<ULONG>::max())
        throwInvalidArgumentException("length > ULONG_MAX");

    IO_STATUS_BLOCK io_status_block;
    LARGE_INTEGER li_offset;
    li_offset.QuadPart = offset;

    NT_CHECK_CALL(NtWriteFile(m_handle.get(),
                              nullptr,
                              nullptr,
                              nullptr,
                              &io_status_block,
                              const_cast<void*>(input),
                              static_cast<ULONG>(length),
                              &li_offset,
                              nullptr));

    if (io_status_block.Information != length)
        throw_runtime_error("Partial write");
}

length_type NTStream::size() const
{
    IO_STATUS_BLOCK io_status_block;
    FILE_STANDARD_INFORMATION info;
    NT_CHECK_CALL(
        NtQueryInformationFile(m_handle.get(),
                               &io_status_block,
                               &info,
                               sizeof(info),
                               static_cast<FILE_INFORMATION_CLASS>(5) /*FileStandardInformation*/));
    return info.EndOfFile.QuadPart;
}

void NTStream::flush()
{
    IO_STATUS_BLOCK io_status_block;
    NT_CHECK_CALL(NtFlushBuffersFile(m_handle.get(), &io_status_block));
}

void NTStream::resize(length_type len)
{
    IO_STATUS_BLOCK io_status_block;
    FILE_END_OF_FILE_INFORMATION info;
    info.EndOfFile.QuadPart = len;

    NT_CHECK_CALL(
        NtSetInformationFile(m_handle.get(),
                             &io_status_block,
                             &info,
                             sizeof(info),
                             static_cast<FILE_INFORMATION_CLASS>(20) /*FileEndOfFileInformation*/));
}

bool NTStream::is_sparse() const noexcept { return true; }

void NTStream::lock(bool exclusive)
{
    IO_STATUS_BLOCK io_status_block;
    LARGE_INTEGER li_offset;
    LARGE_INTEGER li_length;
    li_offset.QuadPart = 0;
    li_length.QuadPart = static_cast<LONGLONG>(-1);    // Lock entire file

    NT_CHECK_CALL(NtLockFile(m_handle.get(),
                             nullptr,
                             nullptr,
                             nullptr,
                             &io_status_block,
                             &li_offset,
                             &li_length,
                             0,
                             false,
                             exclusive));
}

void NTStream::unlock() noexcept
{
    IO_STATUS_BLOCK io_status_block;
    LARGE_INTEGER li_offset;
    LARGE_INTEGER li_length;
    li_offset.QuadPart = 0;
    li_length.QuadPart = static_cast<LONGLONG>(-1);    // Unlock entire file

    // NtUnlockFile doesn't throw exceptions, so we don't need NT_CHECK_CALL
    NtUnlockFile(m_handle.get(), &io_status_block, &li_offset, &li_length, 0);
}
}    // namespace securefs
