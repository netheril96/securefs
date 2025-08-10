#include "nt_exception.h"
#include "myutils.h"
#include "platform.h"

#include <absl/strings/str_format.h>
#include <strsafe.h>
#include <vector>

#include <fuse/fuse_common.h>
#include <winfsp_fuse.h>

namespace securefs
{
NTSTATUS errno_to_ntstatus(int err) { return fsp_fuse_ntstatus_from_errno(fsp_fuse_env(), err); }

int ntstatus_to_errno(NTSTATUS status)
{
    // This is the reverse of errno_to_ntstatus
    switch (status)
    {
    case STATUS_SUCCESS:
        return 0;
    case STATUS_ACCESS_DENIED:
        return 1;
    case STATUS_OBJECT_NAME_NOT_FOUND:
        return 2;
    case STATUS_PROCEDURE_NOT_FOUND:
        return 3;
    case STATUS_CANCELLED:
        return 4;
    case STATUS_IO_DEVICE_ERROR:
        return 5;
    case STATUS_FILE_INVALID:
        return 6;
    case STATUS_INSUFFICIENT_RESOURCES:
        return 7;
    case STATUS_INVALID_IMAGE_FORMAT:
        return 8;
    case STATUS_INVALID_HANDLE:
        return 9;
    case STATUS_ACCESS_VIOLATION:
        return 14;
    case STATUS_DEVICE_BUSY:
        return 16;
    case STATUS_OBJECT_NAME_COLLISION:
        return 17;
    case STATUS_NOT_SAME_DEVICE:
        return 18;
    case STATUS_NO_SUCH_DEVICE:
        return 19;
    case STATUS_NOT_A_DIRECTORY:
        return 20;
    case STATUS_FILE_IS_A_DIRECTORY:
        return 21;
    case STATUS_INVALID_PARAMETER:
        return 22;
    case STATUS_TOO_MANY_OPENED_FILES:
        return 23;
    case STATUS_DISK_FULL:
        return 27;
    case STATUS_MEDIA_WRITE_PROTECTED:
        return 30;
    case STATUS_TOO_MANY_LINKS:
        return 31;
    case STATUS_PIPE_BROKEN:
        return 32;
    case STATUS_POSSIBLE_DEADLOCK:
        return 36;
    case STATUS_NAME_TOO_LONG:
        return 38;
    case STATUS_LOCK_NOT_GRANTED:
        return 39;
    case STATUS_INVALID_DEVICE_REQUEST:
        return 40;
    case STATUS_DIRECTORY_NOT_EMPTY:
        return 41;
    case STATUS_ADDRESS_ALREADY_ASSOCIATED:
        return 100;
    case STATUS_CONNECTION_ACTIVE:
        return 103;
    case STATUS_CONNECTION_ABORTED:
        return 106;
    case STATUS_CONNECTION_REFUSED:
        return 107;
    case STATUS_CONNECTION_RESET:
        return 108;
    case STATUS_HOST_UNREACHABLE:
        return 110;
    case STATUS_REPARSE_POINT_NOT_RESOLVED:
        return 114;
    case STATUS_HOST_DOWN:
        return 116;
    case STATUS_NETWORK_UNREACHABLE:
        return 118;
    case STATUS_END_OF_FILE:
        return 120;
    case STATUS_CONNECTION_INVALID:
        return 121;
    case STATUS_TRANSACTION_TIMED_OUT:
        return 138;
    }
    return 5;    // EIO
}

[[noreturn]] void throw_nt_exception(NTSTATUS status, std::string msg)
{
    throw NTException(status, std::move(msg));
}

std::string NTException::message() const
{
    return absl::StrFormat("NT error 0x%X: %s", m_status, m_msg);
}

long ExceptionBase::ntstatus() const noexcept { return errno_to_ntstatus(error_number()); }

WindowsException::WindowsException(DWORD err,
                                   const wchar_t* funcname,
                                   std::wstring path1,
                                   std::wstring path2)
    : err(err), funcname(funcname), path1(std::move(path1)), path2(std::move(path2))
{
}
WindowsException::WindowsException(DWORD err, const wchar_t* funcname, std::wstring path)
    : err(err), funcname(funcname), path1(std::move(path))
{
}
WindowsException::WindowsException(DWORD err, const wchar_t* funcname)
    : err(err), funcname(funcname)
{
}
WindowsException::~WindowsException() {}

std::string WindowsException::message() const
{
    wchar_t system_buffer[2000];
    if (!FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM,
                        nullptr,
                        err,
                        0,
                        system_buffer,
                        array_length(system_buffer),
                        nullptr))
    {
        system_buffer[0] = 0;
    }

    // Strip any trailing CRLF
    for (ptrdiff_t i = wcslen(system_buffer) - 1; i >= 0; --i)
    {
        if (system_buffer[i] == L'\r' || system_buffer[i] == L'\n')
            system_buffer[i] = 0;
        else
            break;
    }

    std::vector<wchar_t> final_buffer(path1.size() + path2.size() + wcslen(system_buffer)
                                      + wcslen(funcname) + 100);
    if (!path1.empty() && !path2.empty())
    {
        StringCchPrintfW(final_buffer.data(),
                         final_buffer.size(),
                         L"error %lu %s (%s(path1=%s, path2=%s))",
                         err,
                         system_buffer,
                         funcname,
                         path1.c_str(),
                         path2.c_str());
    }
    else if (!path1.empty())
    {
        StringCchPrintfW(final_buffer.data(),
                         final_buffer.size(),
                         L"error %lu %s (%s(path=%s))",
                         err,
                         system_buffer,
                         funcname,
                         path1.c_str());
    }
    else
    {
        StringCchPrintfW(final_buffer.data(),
                         final_buffer.size(),
                         L"error %lu %s (%s)",
                         err,
                         system_buffer,
                         funcname);
    }
    return narrow_string(final_buffer.data());
}
DWORD WindowsException::win32_code() const noexcept { return err; }
long WindowsException::ntstatus() const noexcept { return FspNtStatusFromWin32(win32_code()); }
int WindowsException::error_number() const noexcept { return ntstatus_to_errno(ntstatus()); }

[[noreturn]] void throw_windows_exception(const wchar_t* funcname)
{
    DWORD err = GetLastError();
    throw WindowsException(err, funcname);
}
}    // namespace securefs
