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
int WindowsException::error_number() const noexcept
{
    static const int errorTable[] = {
        0,
        EINVAL,       /* ERROR_INVALID_FUNCTION	1 */
        ENOENT,       /* ERROR_FILE_NOT_FOUND		2 */
        ENOENT,       /* ERROR_PATH_NOT_FOUND		3 */
        EMFILE,       /* ERROR_TOO_MANY_OPEN_FILES	4 */
        EACCES,       /* ERROR_ACCESS_DENIED		5 */
        EBADF,        /* ERROR_INVALID_HANDLE		6 */
        ENOMEM,       /* ERROR_ARENA_TRASHED		7 */
        ENOMEM,       /* ERROR_NOT_ENOUGH_MEMORY	8 */
        ENOMEM,       /* ERROR_INVALID_BLOCK		9 */
        E2BIG,        /* ERROR_BAD_ENVIRONMENT	10 */
        ENOEXEC,      /* ERROR_BAD_FORMAT		11 */
        EACCES,       /* ERROR_INVALID_ACCESS		12 */
        EINVAL,       /* ERROR_INVALID_DATA		13 */
        EFAULT,       /* ERROR_OUT_OF_MEMORY		14 */
        ENOENT,       /* ERROR_INVALID_DRIVE		15 */
        EACCES,       /* ERROR_CURRENT_DIRECTORY	16 */
        EXDEV,        /* ERROR_NOT_SAME_DEVICE	17 */
        ENOENT,       /* ERROR_NO_MORE_FILES		18 */
        EROFS,        /* ERROR_WRITE_PROTECT		19 */
        ENXIO,        /* ERROR_BAD_UNIT		20 */
        EBUSY,        /* ERROR_NOT_READY		21 */
        EIO,          /* ERROR_BAD_COMMAND		22 */
        EIO,          /* ERROR_CRC			23 */
        EIO,          /* ERROR_BAD_LENGTH		24 */
        EIO,          /* ERROR_SEEK			25 */
        EIO,          /* ERROR_NOT_DOS_DISK		26 */
        ENXIO,        /* ERROR_SECTOR_NOT_FOUND	27 */
        EBUSY,        /* ERROR_OUT_OF_PAPER		28 */
        EIO,          /* ERROR_WRITE_FAULT		29 */
        EIO,          /* ERROR_READ_FAULT		30 */
        EIO,          /* ERROR_GEN_FAILURE		31 */
        EACCES,       /* ERROR_SHARING_VIOLATION	32 */
        EACCES,       /* ERROR_LOCK_VIOLATION		33 */
        ENXIO,        /* ERROR_WRONG_DISK		34 */
        ENFILE,       /* ERROR_FCB_UNAVAILABLE	35 */
        ENFILE,       /* ERROR_SHARING_BUFFER_EXCEEDED	36 */
        EINVAL,       /* 37 */
        EINVAL,       /* 38 */
        ENOSPC,       /* ERROR_HANDLE_DISK_FULL	39 */
        EINVAL,       /* 40 */
        EINVAL,       /* 41 */
        EINVAL,       /* 42 */
        EINVAL,       /* 43 */
        EINVAL,       /* 44 */
        EINVAL,       /* 45 */
        EINVAL,       /* 46 */
        EINVAL,       /* 47 */
        EINVAL,       /* 48 */
        EINVAL,       /* 49 */
        ENODEV,       /* ERROR_NOT_SUPPORTED		50 */
        EBUSY,        /* ERROR_REM_NOT_LIST		51 */
        EEXIST,       /* ERROR_DUP_NAME		52 */
        ENOENT,       /* ERROR_BAD_NETPATH		53 */
        EBUSY,        /* ERROR_NETWORK_BUSY		54 */
        ENODEV,       /* ERROR_DEV_NOT_EXIST		55 */
        EAGAIN,       /* ERROR_TOO_MANY_CMDS		56 */
        EIO,          /* ERROR_ADAP_HDW_ERR		57 */
        EIO,          /* ERROR_BAD_NET_RESP		58 */
        EIO,          /* ERROR_UNEXP_NET_ERR		59 */
        EINVAL,       /* ERROR_BAD_REM_ADAP		60 */
        EFBIG,        /* ERROR_PRINTQ_FULL		61 */
        ENOSPC,       /* ERROR_NO_SPOOL_SPACE		62 */
        ENOENT,       /* ERROR_PRINT_CANCELLED	63 */
        ENOENT,       /* ERROR_NETNAME_DELETED	64 */
        EACCES,       /* ERROR_NETWORK_ACCESS_DENIED	65 */
        ENODEV,       /* ERROR_BAD_DEV_TYPE		66 */
        ENOENT,       /* ERROR_BAD_NET_NAME		67 */
        ENFILE,       /* ERROR_TOO_MANY_NAMES		68 */
        EIO,          /* ERROR_TOO_MANY_SESS		69 */
        EAGAIN,       /* ERROR_SHARING_PAUSED		70 */
        EINVAL,       /* ERROR_REQ_NOT_ACCEP		71 */
        EAGAIN,       /* ERROR_REDIR_PAUSED		72 */
        EINVAL,       /* 73 */
        EINVAL,       /* 74 */
        EINVAL,       /* 75 */
        EINVAL,       /* 76 */
        EINVAL,       /* 77 */
        EINVAL,       /* 78 */
        EINVAL,       /* 79 */
        EEXIST,       /* ERROR_FILE_EXISTS		80 */
        EINVAL,       /* 81 */
        ENOSPC,       /* ERROR_CANNOT_MAKE		82 */
        EIO,          /* ERROR_FAIL_I24		83 */
        ENFILE,       /* ERROR_OUT_OF_STRUCTURES	84 */
        EEXIST,       /* ERROR_ALREADY_ASSIGNED	85 */
        EPERM,        /* ERROR_INVALID_PASSWORD	86 */
        EINVAL,       /* ERROR_INVALID_PARAMETER	87 */
        EIO,          /* ERROR_NET_WRITE_FAULT	88 */
        EAGAIN,       /* ERROR_NO_PROC_SLOTS		89 */
        EINVAL,       /* 90 */
        EINVAL,       /* 91 */
        EINVAL,       /* 92 */
        EINVAL,       /* 93 */
        EINVAL,       /* 94 */
        EINVAL,       /* 95 */
        EINVAL,       /* 96 */
        EINVAL,       /* 97 */
        EINVAL,       /* 98 */
        EINVAL,       /* 99 */
        EINVAL,       /* 100 */
        EINVAL,       /* 101 */
        EINVAL,       /* 102 */
        EINVAL,       /* 103 */
        EINVAL,       /* 104 */
        EINVAL,       /* 105 */
        EINVAL,       /* 106 */
        EXDEV,        /* ERROR_DISK_CHANGE		107 */
        EAGAIN,       /* ERROR_DRIVE_LOCKED		108 */
        EPIPE,        /* ERROR_BROKEN_PIPE		109 */
        ENOENT,       /* ERROR_OPEN_FAILED		110 */
        EINVAL,       /* ERROR_BUFFER_OVERFLOW	111 */
        ENOSPC,       /* ERROR_DISK_FULL		112 */
        EMFILE,       /* ERROR_NO_MORE_SEARCH_HANDLES	113 */
        EBADF,        /* ERROR_INVALID_TARGET_HANDLE	114 */
        EFAULT,       /* ERROR_PROTECTION_VIOLATION	115 */
        EINVAL,       /* 116 */
        EINVAL,       /* 117 */
        EINVAL,       /* 118 */
        EINVAL,       /* 119 */
        EINVAL,       /* 120 */
        EINVAL,       /* 121 */
        EINVAL,       /* 122 */
        ENOENT,       /* ERROR_INVALID_NAME		123 */
        EINVAL,       /* 124 */
        EINVAL,       /* 125 */
        EINVAL,       /* 126 */
        ESRCH,        /* ERROR_PROC_NOT_FOUND		127 */
        ECHILD,       /* ERROR_WAIT_NO_CHILDREN	128 */
        ECHILD,       /* ERROR_CHILD_NOT_COMPLETE	129 */
        EBADF,        /* ERROR_DIRECT_ACCESS_HANDLE	130 */
        EINVAL,       /* 131 */
        ESPIPE,       /* ERROR_SEEK_ON_DEVICE		132 */
        EINVAL,       /* 133 */
        EINVAL,       /* 134 */
        EINVAL,       /* 135 */
        EINVAL,       /* 136 */
        EINVAL,       /* 137 */
        EINVAL,       /* 138 */
        EINVAL,       /* 139 */
        EINVAL,       /* 140 */
        EINVAL,       /* 141 */
        EAGAIN,       /* ERROR_BUSY_DRIVE		142 */
        EINVAL,       /* 143 */
        EINVAL,       /* 144 */
        ENOTEMPTY,    /* ERROR_DIR_NOT_EMPTY		145 */
        EINVAL,       /* 146 */
        EINVAL,       /* 147 */
        EINVAL,       /* 148 */
        EINVAL,       /* 149 */
        EINVAL,       /* 150 */
        EINVAL,       /* 151 */
        EINVAL,       /* 152 */
        EINVAL,       /* 153 */
        EINVAL,       /* 154 */
        EINVAL,       /* 155 */
        EINVAL,       /* 156 */
        EINVAL,       /* 157 */
        EACCES,       /* ERROR_NOT_LOCKED		158 */
        EINVAL,       /* 159 */
        EINVAL,       /* 160 */
        ENOENT,       /* ERROR_BAD_PATHNAME	        161 */
        EINVAL,       /* 162 */
        EINVAL,       /* 163 */
        EINVAL,       /* 164 */
        EINVAL,       /* 165 */
        EINVAL,       /* 166 */
        EAGAIN,       /* ERROR_LOCK_FAILED		167 */
        EINVAL,       /* 168 */
        EINVAL,       /* 169 */
        EINVAL,       /* 170 */
        EINVAL,       /* 171 */
        EINVAL,       /* 172 */
        EINVAL,       /* 173 */
        EINVAL,       /* 174 */
        EINVAL,       /* 175 */
        EINVAL,       /* 176 */
        EINVAL,       /* 177 */
        EINVAL,       /* 178 */
        EINVAL,       /* 179 */
        EINVAL,       /* 180 */
        EINVAL,       /* 181 */
        EINVAL,       /* 182 */
        EEXIST,       /* ERROR_ALREADY_EXISTS		183 */
        ECHILD,       /* ERROR_NO_CHILD_PROCESS	184 */
        EINVAL,       /* 185 */
        EINVAL,       /* 186 */
        EINVAL,       /* 187 */
        EINVAL,       /* 188 */
        EINVAL,       /* 189 */
        EINVAL,       /* 190 */
        EINVAL,       /* 191 */
        EINVAL,       /* 192 */
        EINVAL,       /* 193 */
        EINVAL,       /* 194 */
        EINVAL,       /* 195 */
        EINVAL,       /* 196 */
        EINVAL,       /* 197 */
        EINVAL,       /* 198 */
        EINVAL,       /* 199 */
        EINVAL,       /* 200 */
        EINVAL,       /* 201 */
        EINVAL,       /* 202 */
        EINVAL,       /* 203 */
        EINVAL,       /* 204 */
        EINVAL,       /* 205 */
        ENAMETOOLONG, /* ERROR_FILENAME_EXCED_RANGE	206 */
        EINVAL,       /* 207 */
        EINVAL,       /* 208 */
        EINVAL,       /* 209 */
        EINVAL,       /* 210 */
        EINVAL,       /* 211 */
        EINVAL,       /* 212 */
        EINVAL,       /* 213 */
        EINVAL,       /* 214 */
        EINVAL,       /* 215 */
        EINVAL,       /* 216 */
        EINVAL,       /* 217 */
        EINVAL,       /* 218 */
        EINVAL,       /* 219 */
        EINVAL,       /* 220 */
        EINVAL,       /* 221 */
        EINVAL,       /* 222 */
        EINVAL,       /* 223 */
        EINVAL,       /* 224 */
        EINVAL,       /* 225 */
        EINVAL,       /* 226 */
        EINVAL,       /* 227 */
        EINVAL,       /* 228 */
        EINVAL,       /* 229 */
        EPIPE,        /* ERROR_BAD_PIPE		230 */
        EAGAIN,       /* ERROR_PIPE_BUSY		231 */
        EPIPE,        /* ERROR_NO_DATA		232 */
        EPIPE,        /* ERROR_PIPE_NOT_CONNECTED	233 */
        EINVAL,       /* 234 */
        EINVAL,       /* 235 */
        EINVAL,       /* 236 */
        EINVAL,       /* 237 */
        EINVAL,       /* 238 */
        EINVAL,       /* 239 */
        EINVAL,       /* 240 */
        EINVAL,       /* 241 */
        EINVAL,       /* 242 */
        EINVAL,       /* 243 */
        EINVAL,       /* 244 */
        EINVAL,       /* 245 */
        EINVAL,       /* 246 */
        EINVAL,       /* 247 */
        EINVAL,       /* 248 */
        EINVAL,       /* 249 */
        EINVAL,       /* 250 */
        EINVAL,       /* 251 */
        EINVAL,       /* 252 */
        EINVAL,       /* 253 */
        EINVAL,       /* 254 */
        EINVAL,       /* 255 */
        EINVAL,       /* 256 */
        EINVAL,       /* 257 */
        EINVAL,       /* 258 */
        EINVAL,       /* 259 */
        EINVAL,       /* 260 */
        EINVAL,       /* 261 */
        EINVAL,       /* 262 */
        EINVAL,       /* 263 */
        EINVAL,       /* 264 */
        EINVAL,       /* 265 */
        EINVAL,       /* 266 */
        ENOTDIR,      /* ERROR_DIRECTORY		267 */
    };
    if (err >= 0 && err < array_length(errorTable))
        return errorTable[err];
    return EPERM;
}

[[noreturn]] void throw_windows_exception(const wchar_t* funcname)
{
    DWORD err = GetLastError();
    throw WindowsException(err, funcname);
}
}    // namespace securefs
