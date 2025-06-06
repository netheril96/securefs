#ifdef _WIN32
#include "exceptions.h"
#include "lock_enabled.h"
#include "logger.h"
#include "platform.h"

#include <absl/container/inlined_vector.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_split.h>
#include <absl/time/clock.h>
#include <absl/time/time.h>
#include <winfsp/winfsp.h>

#include <cerrno>
#include <limits>
#include <memory>
#include <optional>
#include <stdint.h>
#include <stdlib.h>
#include <sys/utime.h>
#include <time.h>
#include <typeinfo>
#include <vector>    // Added for std::vector

#include <VersionHelpers.h>
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#include <sddl.h>
#include <strsafe.h>

static constexpr std::string_view kSecurefsSymlinkPrefix = R"(\??\UNC\securefs\P)";

static std::string prepend_symlink_prefix(std::string_view path)
{
    std::string modified_path(path);
    std::replace(modified_path.begin(), modified_path.end(), '/', '\\');
    return absl::StrCat(kSecurefsSymlinkPrefix, modified_path);
}

static std::string remove_symlink_prefix(std::string_view path)
{
    if (absl::StartsWith(path, kSecurefsSymlinkPrefix))
    {
        std::string stripped_path(path.substr(kSecurefsSymlinkPrefix.size()));
        std::replace(stripped_path.begin(), stripped_path.end(), '\\', '/');
        return stripped_path;
    }
    return std::string(path);
}

static inline uint64_t convert_dword_pair(uint64_t low_part, uint64_t high_part)
{
    return low_part | (high_part << 32);
}

static void filetime_to_unix_time(const FILETIME* ft, fuse_timespec* out)
{
    long long ll = convert_dword_pair(ft->dwLowDateTime, ft->dwHighDateTime) - 116444736000000000LL;
    static const long long FACTOR = 10000000LL;
    out->tv_sec = ll / FACTOR;
    out->tv_nsec = (ll % FACTOR) * 100;
}

template <class TimeSpec>
static FILETIME unix_time_to_filetime(const TimeSpec* t)
{
    long long ll = t->tv_sec * 10000000LL + t->tv_nsec / 100LL + 116444736000000000LL;
    FILETIME res;
    res.dwLowDateTime = (DWORD)ll;
    res.dwHighDateTime = (DWORD)(ll >> 32);
    return res;
}

template <class TimeSpec>
static FILETIME unix_time_to_filetime(const TimeSpec& t)
{
    return unix_time_to_filetime(&t);
}

static const DWORD MAX_SINGLE_BLOCK = std::numeric_limits<DWORD>::max();

namespace securefs
{
class WindowsException : public SystemException
{
private:
    DWORD err;
    const wchar_t* funcname;
    std::wstring path1, path2;

public:
    explicit WindowsException(DWORD err,
                              const wchar_t* funcname,
                              std::wstring path1,
                              std::wstring path2)
        : err(err), funcname(funcname), path1(std::move(path1)), path2(std::move(path2))
    {
    }
    explicit WindowsException(DWORD err, const wchar_t* funcname, std::wstring path)
        : err(err), funcname(funcname), path1(std::move(path))
    {
    }
    explicit WindowsException(DWORD err, const wchar_t* funcname) : err(err), funcname(funcname) {}
    ~WindowsException() {}

    std::string message() const override
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
    DWORD win32_code() const noexcept { return err; }
    int error_number() const noexcept override
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
};

[[noreturn]] void throw_windows_exception(const wchar_t* funcname)
{
    DWORD err = GetLastError();
    throw WindowsException(err, funcname);
}

#define THROW_WINDOWS_EXCEPTION(err, exp)                                                          \
    do                                                                                             \
    {                                                                                              \
        DWORD code = err;                                                                          \
        throw WindowsException(code, exp);                                                         \
    } while (0)

#define THROW_WINDOWS_EXCEPTION_WITH_PATH(err, exp, path)                                          \
    do                                                                                             \
    {                                                                                              \
        DWORD code = err;                                                                          \
        throw WindowsException(code, exp, path);                                                   \
    } while (0)

#define THROW_WINDOWS_EXCEPTION_WITH_TWO_PATHS(err, exp, path1, path2)                             \
    do                                                                                             \
    {                                                                                              \
        DWORD code = err;                                                                          \
        throw WindowsException(code, exp, path1, path2);                                           \
    } while (0)

#define CHECK_CALL(exp)                                                                            \
    if (!(exp))                                                                                    \
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"" #exp);

static void stat_file_handle(HANDLE hd, fuse_stat* st)
{
    memset(st, 0, sizeof(*st));
    BY_HANDLE_FILE_INFORMATION info;
    CHECK_CALL(GetFileInformationByHandle(hd, &info));
    filetime_to_unix_time(&info.ftLastAccessTime, &st->st_atim);
    filetime_to_unix_time(&info.ftLastWriteTime, &st->st_mtim);
    filetime_to_unix_time(&info.ftCreationTime, &st->st_birthtim);
    st->st_ctim = st->st_mtim;
    st->st_nlink = static_cast<fuse_nlink_t>(info.nNumberOfLinks);
    st->st_uid = securefs::OSService::getuid();
    st->st_gid = securefs::OSService::getgid();
    st->st_dev = info.dwVolumeSerialNumber;
    st->st_ino = convert_dword_pair(info.nFileIndexLow, info.nFileIndexHigh);
    st->st_size = convert_dword_pair(info.nFileSizeLow, info.nFileSizeHigh);
    st->st_blksize = 4096;
    st->st_blocks = (st->st_size + 4095) / 4096 * (4096 / 512);
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    {
        st->st_mode = S_IFLNK | 0777;

        std::vector<char> buffer(65535);
        DWORD returned_length;
        if (DeviceIoControl(hd,
                            FSCTL_GET_REPARSE_POINT,
                            nullptr,
                            0,
                            buffer.data(),
                            static_cast<DWORD>(buffer.size()),
                            &returned_length,
                            nullptr))
        {
            auto reparse_data = reinterpret_cast<REPARSE_DATA_BUFFER*>(buffer.data());
            if (reparse_data->ReparseTag != IO_REPARSE_TAG_SYMLINK)
            {
                THROW_WINDOWS_EXCEPTION(
                    ERROR_INVALID_PARAMETER,
                    L"DeviceIoControl(FSCTL_GET_REPARSE_POINT) returned invalid reparse tag");
            }
            std::wstring_view target(
                reparse_data->SymbolicLinkReparseBuffer.PathBuffer
                    + reparse_data->SymbolicLinkReparseBuffer.SubstituteNameOffset
                        / sizeof(wchar_t),
                reparse_data->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(wchar_t));
            size_t target_size = narrow_string(target).size();
            st->st_size = target_size > kSecurefsSymlinkPrefix.size()
                ? target_size - kSecurefsSymlinkPrefix.size()
                : 0;
        }
    }
    else if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        st->st_mode = S_IFDIR | 0755;
    else
        st->st_mode = S_IFREG | 0755;
}

class WindowsFileStream final : public FileStream
{
private:
    HANDLE m_handle;

private:
    void write32(const void* input, offset_type offset, DWORD length)
    {
        OVERLAPPED ol;
        memset(&ol, 0, sizeof(ol));
        ol.Offset = static_cast<DWORD>(offset);
        ol.OffsetHigh = static_cast<DWORD>(offset >> 32);

        DWORD writelen;
        CHECK_CALL(WriteFile(m_handle, input, length, &writelen, &ol));
        if (writelen != length)
            throwVFSException(EIO);
    }

    void write32(const void* input, DWORD length)
    {
        DWORD writelen;
        CHECK_CALL(WriteFile(m_handle, input, length, &writelen, nullptr));
        if (writelen != length)
            throwVFSException(EIO);
    }

    length_type read32(void* output, offset_type offset, DWORD length)
    {
        OVERLAPPED ol;
        memset(&ol, 0, sizeof(ol));
        ol.Offset = static_cast<DWORD>(offset);
        ol.OffsetHigh = static_cast<DWORD>(offset >> 32);

        DWORD readlen;
        if (!ReadFile(m_handle, output, length, &readlen, &ol))
        {
            DWORD err = GetLastError();
            if (err == ERROR_HANDLE_EOF)
                return 0;
            THROW_WINDOWS_EXCEPTION(err, L"ReadFile");
        }
        return readlen;
    }

    length_type read32(void* output, DWORD length)
    {
        DWORD readlen;
        if (!ReadFile(m_handle, output, length, &readlen, nullptr))
        {
            DWORD err = GetLastError();
            if (err == ERROR_HANDLE_EOF)
                return 0;
            THROW_WINDOWS_EXCEPTION(err, L"ReadFile");
        }
        return readlen;
    }

public:
    explicit WindowsFileStream(const std::wstring& path, int flags, unsigned mode)
        : m_handle(INVALID_HANDLE_VALUE)
    {
        DWORD access_flags = 0;
        switch (flags & O_ACCMODE)
        {
        case O_RDONLY:
            access_flags = GENERIC_READ;
            break;
        case O_WRONLY:
            access_flags = GENERIC_WRITE;
            break;
        case O_RDWR:
            access_flags = GENERIC_READ | GENERIC_WRITE;
            break;
        default:
            throwVFSException(EINVAL);
        }

        DWORD create_flags = 0;
        if (flags & O_CREAT)
        {
            if (flags & O_EXCL)
                create_flags = CREATE_NEW;
            else if (flags & O_TRUNC)
                throwInvalidArgumentException(
                    "On Windows, O_TRUNC cannot be specified together with O_CREAT");
            else
                create_flags = OPEN_ALWAYS;
        }
        else if (flags & O_TRUNC)
        {
            create_flags = TRUNCATE_EXISTING;
        }
        else
        {
            create_flags = OPEN_EXISTING;
        }

        m_handle = CreateFileW(path.c_str(),
                               access_flags,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr,
                               create_flags,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                               nullptr);
        if (m_handle == INVALID_HANDLE_VALUE)
        {
            DWORD err = GetLastError();
            throw WindowsException(err, L"CreateFileW", path);
        }
    }

    ~WindowsFileStream() { CloseHandle(m_handle); }

    void lock(bool exclusive) override
    {
        if (!securefs::is_lock_enabled())
        {
            return;
        }
        OVERLAPPED o;
        memset(&o, 0, sizeof(o));
        CHECK_CALL(LockFileEx(m_handle,
                              exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0,
                              0,
                              std::numeric_limits<DWORD>::max(),
                              std::numeric_limits<DWORD>::max(),
                              &o));
    }

    void unlock() noexcept override
    {
        if (!securefs::is_lock_enabled())
        {
            return;
        }
        OVERLAPPED o;
        memset(&o, 0, sizeof(o));
        (void)(UnlockFileEx(
            m_handle, 0, std::numeric_limits<DWORD>::max(), std::numeric_limits<DWORD>::max(), &o));
    }

    void close() noexcept override
    {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }

    length_type read(void* output, offset_type offset, length_type length) override
    {
        length_type total = 0;
        while (length > MAX_SINGLE_BLOCK)
        {
            length_type readlen = read32(output, offset, MAX_SINGLE_BLOCK);
            if (readlen == 0)
                return total;
            length -= readlen;
            offset += readlen;
            output = static_cast<char*>(output) + readlen;
            total += readlen;
        }
        total += read32(output, offset, static_cast<DWORD>(length));
        return total;
    }

    length_type sequential_read(void* output, length_type length) override
    {
        length_type total = 0;
        while (length > MAX_SINGLE_BLOCK)
        {
            length_type readlen = read32(output, MAX_SINGLE_BLOCK);
            if (readlen == 0)
                return total;
            length -= readlen;
            output = static_cast<char*>(output) + readlen;
            total += readlen;
        }
        total += read32(output, static_cast<DWORD>(length));
        return total;
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        while (length > MAX_SINGLE_BLOCK)
        {
            write32(input, offset, MAX_SINGLE_BLOCK);
            length -= MAX_SINGLE_BLOCK;
            offset += MAX_SINGLE_BLOCK;
            input = static_cast<const char*>(input) + MAX_SINGLE_BLOCK;
        }
        write32(input, offset, static_cast<DWORD>(length));
    }

    void sequential_write(const void* input, length_type length) override
    {
        while (length > MAX_SINGLE_BLOCK)
        {
            write32(input, MAX_SINGLE_BLOCK);
            length -= MAX_SINGLE_BLOCK;
            input = static_cast<const char*>(input) + MAX_SINGLE_BLOCK;
        }
        write32(input, static_cast<DWORD>(length));
    }

    length_type size() const override
    {
        _LARGE_INTEGER SIZE;
        CHECK_CALL(GetFileSizeEx(m_handle, &SIZE));
        return SIZE.QuadPart;
    }

    void flush() override {}

    void resize(length_type len) override
    {
        LARGE_INTEGER llen;
        llen.QuadPart = len;
        CHECK_CALL(SetFilePointerEx(m_handle, llen, nullptr, FILE_BEGIN));
        CHECK_CALL(SetEndOfFile(m_handle));
    }

    length_type optimal_block_size() const noexcept override { return 4096; }

    void fsync() override { CHECK_CALL(FlushFileBuffers(m_handle)); }
    void utimens(const fuse_timespec ts[2]) override
    {
        FILETIME access_time, mod_time;
        if (!ts)
        {
            access_time = unix_time_to_filetime(absl::ToTimespec(absl::Now()));
            mod_time = access_time;
        }
        else
        {
            access_time = unix_time_to_filetime(ts + 0);
            mod_time = unix_time_to_filetime(ts + 1);
        }
        CHECK_CALL(SetFileTime(m_handle, nullptr, &access_time, &mod_time));
    }
    void fstat(fuse_stat* st) const override { stat_file_handle(m_handle, st); }
    bool is_sparse() const noexcept override { return true; }
};

OSService::OSService() : m_root_handle(INVALID_HANDLE_VALUE) {}

OSService::~OSService() { CloseHandle(m_root_handle); }

bool OSService::is_absolute(std::string_view path)
{
    return path.empty() || path[0] == '/' || path[0] == '\\'
        || (path.size() >= 2 && path[1] == ':');
}

native_string_type OSService::concat_and_norm(std::string_view base_dir, std::string_view path)
{
    if (base_dir.empty() || is_absolute(path))
    {
        return widen_string(path);
    }
    if (!is_absolute(base_dir))
    {
        throwInvalidArgumentException(
            absl::StrCat("base_dir must be an absolute path, yet we received ", base_dir));
    }
    std::vector<char> buffer;
    buffer.reserve(2 * (base_dir.size() + path.size()) + 15);
    buffer.insert(buffer.end(), base_dir.begin(), base_dir.end());
    buffer.push_back('\\');
    buffer.insert(buffer.end(), path.begin(), path.end());

    absl::InlinedVector<std::string_view, 32> pieces;
    for (std::string_view p :
         absl::StrSplit(std::string_view(buffer.data(), buffer.size()),
                        absl::ByAnyChar("/\\"),
                        [](std::string_view p) { return !p.empty() && p != "."; }))
    {
        if (p == "..")
        {
            if (!pieces.empty())
            {
                pieces.pop_back();
            }
        }
        else
        {
            pieces.push_back(p);
        }
    }
    size_t offset = buffer.size();

    static constexpr std::string_view LONG_PATH_PREFIX = R"(\\)";

    if (!absl::StartsWith(base_dir, LONG_PATH_PREFIX))
    {
        buffer.push_back('\\');
        buffer.push_back('\\');
        buffer.push_back('?');
    }
    else
    {
        buffer.push_back('\\');
    }
    for (std::string_view p : pieces)
    {
        buffer.push_back('\\');
        buffer.insert(buffer.end(), p.begin(), p.end());
    }
    return widen_string(std::string_view(buffer.data() + offset, buffer.size() - offset));
}

OSService::OSService(const std::string& path)
{
    auto wide_path = widen_string(path);
    std::wstring fullname(33000, 0);
    DWORD size = GetFullPathNameW(
        wide_path.c_str(), static_cast<DWORD>(fullname.size()), &fullname[0], nullptr);
    if (size <= 0)
    {
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"GetFullPathNameW", wide_path);
    }
    fullname.resize(size);
    m_root_handle = CreateFileW(fullname.c_str(),
                                GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS,
                                nullptr);
    if (m_root_handle == INVALID_HANDLE_VALUE)
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"CreateFileW", fullname);
    m_dir_name = narrow_string(fullname);
}

std::shared_ptr<FileStream>
OSService::open_file_stream(const std::string& path, int flags, unsigned mode) const
{
    return std::make_shared<WindowsFileStream>(norm_path(path), flags, mode);
}

void OSService::remove_file(const std::string& path) const
{
    CHECK_CALL(DeleteFileW(norm_path(path).c_str()));
}

void OSService::remove_directory(const std::string& path) const
{
    CHECK_CALL(RemoveDirectoryW(norm_path(path).c_str()));
}

void OSService::lock() const
{
    if (!securefs::is_lock_enabled())
    {
        return;
    }
    fprintf(stderr,
            "Warning: Windows does not support directory locking. "
            "Be careful not to mount the same data directory multiple times!\n");
}

void OSService::mkdir(const std::string& path, unsigned mode) const
{
    auto npath = norm_path(path);
    if (CreateDirectoryW(npath.c_str(), nullptr) == 0)
    {
        DWORD err = GetLastError();
        THROW_WINDOWS_EXCEPTION_WITH_PATH(err, L"CreateDirectory", npath);
    }
}

void OSService::ensure_directory(const std::string& path, unsigned mode) const
{
    auto npath = norm_path(path);
    if (CreateDirectoryW(npath.c_str(), nullptr) == 0)
    {
        DWORD err = GetLastError();
        if (err == ERROR_ALREADY_EXISTS)
        {
            return;
        }
        THROW_WINDOWS_EXCEPTION_WITH_PATH(err, L"CreateDirectory", npath);
    }
}

bool OSService::remove_file_nothrow(const std::string& path) const noexcept
{
    return DeleteFileW(norm_path(path).c_str());
}

bool OSService::remove_directory_nothrow(const std::string& path) const noexcept
{
    return RemoveDirectoryW(norm_path(path).c_str());
}

void OSService::statfs(fuse_statvfs* fs_info) const
{
    memset(fs_info, 0, sizeof(*fs_info));
    ULARGE_INTEGER FreeBytesAvailable, TotalNumberOfBytes, TotalNumberOfFreeBytes;
    DWORD namemax = 0;
    CHECK_CALL(GetDiskFreeSpaceExW(
        norm_path(".").c_str(), &FreeBytesAvailable, &TotalNumberOfBytes, &TotalNumberOfFreeBytes));
    CHECK_CALL(GetVolumeInformationByHandleW(
        m_root_handle, nullptr, 0, nullptr, &namemax, nullptr, nullptr, 0));
    auto maximum = static_cast<unsigned>(-1);
    fs_info->f_bsize = 4096;
    fs_info->f_frsize = fs_info->f_bsize;
    fs_info->f_bfree = TotalNumberOfFreeBytes.QuadPart / fs_info->f_bsize;
    fs_info->f_blocks = TotalNumberOfBytes.QuadPart / fs_info->f_bsize;
    fs_info->f_bavail = FreeBytesAvailable.QuadPart / fs_info->f_bsize;
    fs_info->f_files = maximum;
    fs_info->f_ffree = maximum;
    fs_info->f_favail = maximum;
    fs_info->f_namemax = namemax;
}

void OSService::utimens(const std::string& path, const fuse_timespec ts[2]) const
{
    FILETIME atime, mtime;
    if (!ts)
    {
        atime = unix_time_to_filetime(absl::ToTimespec(absl::Now()));
        mtime = atime;
    }
    else
    {
        atime = unix_time_to_filetime(ts);
        mtime = unix_time_to_filetime(ts + 1);
    }
    auto npath = norm_path(path);
    HANDLE hd = CreateFileW(npath.c_str(),
                            FILE_WRITE_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                            nullptr);
    if (hd == INVALID_HANDLE_VALUE)
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"CreateFileW", npath);
    DEFER(CloseHandle(hd));
    CHECK_CALL(SetFileTime(hd, nullptr, &atime, &mtime));
}

bool OSService::stat(const std::string& path, fuse_stat* stat) const
{
    if (path == "." && m_root_handle != INVALID_HANDLE_VALUE)
    {
        // Special case which occurs very frequently
        stat_file_handle(m_root_handle, stat);
        return true;
    }
    auto npath = norm_path(path);
    HANDLE handle = CreateFileW(npath.c_str(),
                                FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                                nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        if (err == ERROR_PATH_NOT_FOUND || err == ERROR_FILE_NOT_FOUND || err == ERROR_NOT_FOUND)
            return false;
        THROW_WINDOWS_EXCEPTION_WITH_PATH(err, L"CreateFileW", npath);
    }

    DEFER(CloseHandle(handle));
    stat_file_handle(handle, stat);
    return true;
}

void OSService::link(const std::string& source, const std::string& dest) const
{
    throwVFSException(ENOSYS);
}
void OSService::chmod(const std::string& path, fuse_mode_t mode) const { (void)0; }
void OSService::chown(const std::string&, fuse_uid_t, fuse_gid_t) const { (void)0; }

ssize_t OSService::readlink(const std::string& path, char* output, size_t size) const
{
    auto npath = norm_path(path);
    HANDLE handle = CreateFileW(npath.c_str(),
                                GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                                nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"CreateFileW", npath);
    }
    DEFER(CloseHandle(handle));

    std::vector<char> buffer(65535);
    DWORD returned_length;
    if (!DeviceIoControl(handle,
                         FSCTL_GET_REPARSE_POINT,
                         nullptr,
                         0,
                         buffer.data(),
                         static_cast<DWORD>(buffer.size()),
                         &returned_length,
                         nullptr))
    {
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"DeviceIoControl", npath);
    }

    auto reparse_data = reinterpret_cast<REPARSE_DATA_BUFFER*>(buffer.data());
    if (reparse_data->ReparseTag != IO_REPARSE_TAG_SYMLINK)
    {
        throwVFSException(EINVAL);
    }

    std::wstring_view target(
        reparse_data->SymbolicLinkReparseBuffer.PathBuffer
            + reparse_data->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(wchar_t),
        reparse_data->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(wchar_t));
    std::string stripped = remove_symlink_prefix(narrow_string(target));
    size_t copy_length = std::min(size, stripped.size());
    if (output && size > 0)
    {
        memcpy(output, stripped.data(), copy_length);
    }
    return copy_length;
}

void OSService::symlink(const std::string& to, const std::string& from) const
{
    auto transformed_target = widen_string(prepend_symlink_prefix(to));
    auto wide_source = norm_path(from);

    if (!CreateSymbolicLinkW(wide_source.c_str(),
                             transformed_target.c_str(),
                             SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
    {
        DWORD err = GetLastError();
        THROW_WINDOWS_EXCEPTION_WITH_TWO_PATHS(
            err, L"CreateSymbolicLinkW", wide_source, transformed_target);
    }
}

void OSService::rename(const std::string& a, const std::string& b) const
{
    auto wa = norm_path(a);
    auto wb = norm_path(b);
    if (!MoveFileExW(wa.c_str(), wb.c_str(), MOVEFILE_REPLACE_EXISTING))
        THROW_WINDOWS_EXCEPTION_WITH_TWO_PATHS(GetLastError(), L"MoveFileExW", wa, wb);
}

int64_t OSService::raise_fd_limit() noexcept
{
    // The handle limit on Windows is high enough that no adjustments are necessary
    return std::numeric_limits<int32_t>::max();
}

void OSService::enter_background()
{
    WARN_LOG("Entering background mode is not allowed on Windows, because you can't unmount then");
}

void OSService::set_file_descriptor_in_binary_mode(int fd)
{
    if (_setmode(fd, _O_BINARY) == -1)
    {
        THROW_POSIX_EXCEPTION(errno, "Failed to set file descriptor to binary mode");
    }
}

class WindowsDirectoryTraverser final : public DirectoryTraverser
{
private:
    std::wstring m_pattern;
    WIN32_FIND_DATAW m_data;
    HANDLE m_handle;
    bool m_is_initial{};

public:
    explicit WindowsDirectoryTraverser(std::wstring pattern)
        : m_pattern(std::move(pattern)), m_handle(INVALID_HANDLE_VALUE)
    {
        rewind();
    }

    ~WindowsDirectoryTraverser()
    {
        if (m_handle != INVALID_HANDLE_VALUE)
            FindClose(m_handle);
    }

    void rewind() override
    {
        if (m_is_initial)
            return;    // Already at the beginning
        if (m_handle != INVALID_HANDLE_VALUE)
            FindClose(m_handle);
        m_handle = FindFirstFileW(m_pattern.c_str(), &m_data);
        if (m_handle == INVALID_HANDLE_VALUE)
        {
            THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"FindFirstFileW", m_pattern);
        }
        m_is_initial = true;
    }

    bool next(std::string* name, fuse_stat* st) override
    {
        if (m_is_initial)
        {
            m_is_initial = false;
        }
        else
        {
            if (!FindNextFileW(m_handle, &m_data))
            {
                DWORD err = GetLastError();
                if (err == ERROR_NO_MORE_FILES)
                    return false;
                THROW_WINDOWS_EXCEPTION_WITH_PATH(err, L"FindNextFileW", m_pattern);
            }
        }

        if (name)
            *name = narrow_string(m_data.cFileName);
        if (st)
        {
            if (m_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            {
                st->st_mode = 0777 | S_IFLNK;
            }
            else if (m_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                st->st_mode = 0755 | S_IFDIR;
            }
            else
            {
                st->st_mode = 0755 | S_IFREG;
            }
            st->st_size = convert_dword_pair(m_data.nFileSizeLow, m_data.nFileSizeHigh);
            filetime_to_unix_time(&m_data.ftCreationTime, &st->st_birthtim);
            filetime_to_unix_time(&m_data.ftLastAccessTime, &st->st_atim);
            filetime_to_unix_time(&m_data.ftLastWriteTime, &st->st_mtim);
            st->st_ctim = st->st_mtim;
            st->st_nlink = 1;
            st->st_blksize = 4096;
            st->st_blocks = st->st_size / 512;
        }
        return true;
    }
};

std::unique_ptr<DirectoryTraverser> OSService::create_traverser(const std::string& dir) const
{
    return securefs::make_unique<WindowsDirectoryTraverser>(norm_path(dir) + L"\\*");
}

uint32_t OSService::getuid() noexcept { return 0; }

uint32_t OSService::getgid() noexcept { return 0; }

void OSService::get_current_time(fuse_timespec& current_time)
{
    auto ts = absl::ToTimespec(absl::Now());
    current_time.tv_sec = ts.tv_sec;
    current_time.tv_nsec = ts.tv_nsec;
}

void OSService::get_current_time_in_tm(struct tm* tm, int* ns)
{
    fuse_timespec spec;
    get_current_time(spec);
    time_t tts = spec.tv_sec;
    gmtime_s(tm, &tts);
    *ns = spec.tv_nsec;
}

void OSService::read_password_no_confirmation(const char* prompt,
                                              CryptoPP::AlignedSecByteBlock* output)
{
    byte buffer[4000];
    DEFER(CryptoPP::SecureWipeBuffer(buffer, array_length(buffer)));
    size_t bufsize = 0;

    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD old_mode, new_mode;
    if (GetConsoleMode(in, &old_mode))
    {
        // Success, guess we are reading from user input instead of a pipe
        fputs(prompt, stderr);
        fflush(stderr);

        new_mode = old_mode & ~(DWORD)ENABLE_ECHO_INPUT;
        SetConsoleMode(in, new_mode);
    }

    while (1)
    {
        int c = getchar();
        if (c == '\r' || c == '\n' || c == EOF)
            break;
        if (bufsize < array_length(buffer))
        {
            buffer[bufsize] = static_cast<byte>(c);
            ++bufsize;
        }
        else
        {
            throw_runtime_error("Password exceeds 4000 characters");
        }
    }

    if (SetConsoleMode(in, old_mode))
        putc('\n', stderr);
    output->resize(bufsize);
    memcpy(output->data(), buffer, bufsize);
}

void OSService::read_password_with_confirmation(const char* prompt,
                                                CryptoPP::AlignedSecByteBlock* output)
{
    CryptoPP::AlignedSecByteBlock another;
    read_password_no_confirmation(prompt, output);
    read_password_no_confirmation("Again: ", &another);
    if (output->size() != another.size()
        || memcmp(output->data(), another.data(), another.size()) != 0)
        throw_runtime_error("Password mismatch!");
}

std::string OSService::stringify_system_error(int errcode)
{
    char buffer[4000];
    strerror_s(buffer, array_length(buffer), errcode);
    return buffer;
}

namespace
{
    struct ConsoleTestResult
    {
        bool is_console = false;
        HANDLE handle = INVALID_HANDLE_VALUE;
        DWORD mode = 0;
    };

    ConsoleTestResult test_console(FILE* fp)
    {
        if (!fp)
        {
            return {};
        }
        int fd = _fileno(fp);
        if (fd < 0)
        {
            return {};
        }
        auto h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
        if (h == INVALID_HANDLE_VALUE)
        {
            return {};
        }
        ConsoleTestResult result;
        result.handle = h;
        result.is_console = GetConsoleMode(h, &result.mode);
        return result;
    }
}    // namespace

std::unique_ptr<ConsoleColourSetter> ConsoleColourSetter::create_setter(FILE* fp)
{
    auto t = test_console(fp);
    if (!t.is_console)
        return {};
    if (!SetConsoleMode(t.handle, t.mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    {
        return {};
    }
    return securefs::make_unique<POSIXColourSetter>(fp);
}

std::unique_ptr<const char, void (*)(const char*)> get_type_name(const std::exception& e) noexcept
{
    return {typeid(e).name(), [](const char*) { /* no op */ }};
}

const char* PATH_SEPARATOR_STRING = "\\";
const char PATH_SEPARATOR_CHAR = '\\';

void windows_init(void)
{
    static auto original_cp = ::GetConsoleOutputCP();
    ::SetConsoleOutputCP(CP_UTF8);
    atexit([]() { ::SetConsoleOutputCP(original_cp); });
    _set_invalid_parameter_handler(
        [](wchar_t const*, wchar_t const*, wchar_t const*, unsigned int, uintptr_t) {});

    if (test_console(stdout).is_console)
    {
        setvbuf(stdout, nullptr, _IOLBF, 65536);
    }
    if (test_console(stderr).is_console)
    {
        setvbuf(stderr, nullptr, _IOLBF, 65536);
    }
    if (::FspLoad(nullptr) != STATUS_SUCCESS)
    {
        fputs("SecureFS cannot load WinFsp. Please make sure you have WinFsp properly installed.\n",
              stderr);
        abort();
    }
}

bool OSService::is_process_running(pid_t pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process != nullptr)
    {
        DEFER(CloseHandle(process));
        return true;
    }
    DWORD error = GetLastError();
    if (error == ERROR_INVALID_PARAMETER)
    {
        // The PID does not exist.
        return false;
    }
    // If GetLastError is ERROR_ACCESS_DENIED, the process exists but
    // we don't have permission to query it. For the purpose of
    // "is it running", we should consider it running.
    // Other errors might indicate temporary issues, but for simplicity,
    // we'll assume if it's not ERROR_INVALID_PARAMETER, the PID likely exists.
    return true;
}
pid_t OSService::get_current_process_id() { return GetCurrentProcessId(); }

unsigned OSService::get_cmd_for_query_ioctl() noexcept
{
    return FSP_FUSE_IOCTL('s', 0, (unsigned)sizeof(unsigned));
}
unsigned OSService::get_cmd_for_trigger_unmount_ioctl() noexcept
{
    return FSP_FUSE_IOCTL('s', 0, 0);
}
bool OSService::query_if_mounted_by_ioctl() const
{
    unsigned magic = 0;
    return DeviceIoControl(m_root_handle,
                           FSP_FUSE_CTLCODE_FROM_IOCTL(get_cmd_for_query_ioctl()),
                           nullptr,
                           0,
                           &magic,
                           sizeof(magic),
                           nullptr,
                           nullptr)
        && magic == get_magic_for_mounted_status();
}
void OSService::trigger_unmount_by_ioctl() const
{
    CHECK_CALL(DeviceIoControl(m_root_handle,
                               FSP_FUSE_CTLCODE_FROM_IOCTL(get_cmd_for_trigger_unmount_ioctl()),
                               nullptr,
                               0,
                               nullptr,
                               0,
                               nullptr,
                               nullptr));
}

std::string OSService::win_quote_argv(std::string_view arg)
{
    // Rules based on CommandLineToArgvW parsing:
    // 1. Arguments are separated by whitespace (space, tab).
    // 2. Double quotes ("") delimit arguments with whitespace.
    // 3. A double quote preceded by a backslash (\"") is a literal quote.
    // 4. Backslashes are literal unless they precede a double quote.
    // 5. 2N backslashes + "" -> N backslashes + delimiter quote.
    // 6. 2N+1 backslashes + "" -> N backslashes + literal quote.

    // Quoting is needed if the argument is empty, contains whitespace, or contains a double quote.
    bool needs_quoting = arg.empty() || arg.find_first_of(" \t\"") != std::string_view::npos;

    if (!needs_quoting)
    {
        return std::string(arg);
    }

    std::string quoted_arg;
    quoted_arg.reserve(arg.size() + 2);    // Estimate minimum size
    quoted_arg.push_back('"');

    size_t i = 0;
    while (i < arg.size())
    {
        if (arg[i] == '\\')
        {
            size_t backslash_count = 0;
            while (i + backslash_count < arg.size() && arg[i + backslash_count] == '\\')
            {
                backslash_count++;
            }
            // Append the backslashes
            for (size_t j = 0; j < backslash_count; ++j)
            {
                quoted_arg.push_back('\\');
            }
            // If the sequence is followed by a quote, double the backslashes again
            if (i + backslash_count < arg.size() && arg[i + backslash_count] == '"')
            {
                for (size_t j = 0; j < backslash_count; ++j)
                {
                    quoted_arg.push_back('\\');
                }
            }
            i += backslash_count;
        }
        else if (arg[i] == '"')
        {
            // Escape the quote
            quoted_arg.push_back('\\');
            quoted_arg.push_back('"');
            i++;
        }
        else
        {
            // Append other characters as is
            quoted_arg.push_back(arg[i]);
            i++;
        }
    }

    quoted_arg.push_back('"');
    return quoted_arg;
}

int OSService::execute_child_process_with_data_and_wait(absl::Span<const std::string_view> args,
                                                        std::string_view stdin_data)
{
    if (args.empty())
    {
        throwInvalidArgumentException("Empty argument list");
    }

    std::string cmd_line_utf8;
    for (size_t i = 0; i < args.size(); ++i)
    {
        cmd_line_utf8 += win_quote_argv(args[i]);
        if (i < args.size() - 1)
        {
            cmd_line_utf8 += " ";
        }
    }
    std::wstring cmd_line_utf16 = widen_string(cmd_line_utf8);
    // CreateProcessW may modify the command line string, so pass a mutable copy.
    std::vector<wchar_t> mutable_cmd_line(cmd_line_utf16.begin(), cmd_line_utf16.end());
    mutable_cmd_line.push_back(L'\0');

    HANDLE hStdInRead = INVALID_HANDLE_VALUE;
    HANDLE hStdInWrite = INVALID_HANDLE_VALUE;
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    HANDLE hThread = INVALID_HANDLE_VALUE;

    // Ensure all handles are closed eventually
    DEFER({
        if (hStdInRead != INVALID_HANDLE_VALUE)
            CloseHandle(hStdInRead);
        if (hStdInWrite != INVALID_HANDLE_VALUE)
            CloseHandle(hStdInWrite);
        if (hProcess != INVALID_HANDLE_VALUE)
            CloseHandle(hProcess);
        if (hThread != INVALID_HANDLE_VALUE)
            CloseHandle(hThread);
    });

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;    // Allow handles to be inherited
    sa.lpSecurityDescriptor = nullptr;

    // Create a pipe for the child process's STDIN.
    if (!CreatePipe(&hStdInRead, &hStdInWrite, &sa, 0))
    {
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"CreatePipe for stdin");
    }

    // Ensure the write handle to the pipe for STDIN is not inherited by the child.
    if (!SetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0))
    {
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"SetHandleInformation for hStdInWrite");
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);      // Inherit parent's stderr
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);    // Inherit parent's stdout
    si.hStdInput = hStdInRead;                          // Child's stdin is the read end of our pipe
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;    // Hide the console window

    // Create the child process.
    if (!CreateProcessW(nullptr,                    // No module name (use command line)
                        mutable_cmd_line.data(),    // Command line (mutable)
                        nullptr,                    // Process handle not inheritable
                        nullptr,                    // Thread handle not inheritable
                        TRUE,                // Set handle inheritance to TRUE for si.hStdInput
                        CREATE_NO_WINDOW,    // Creation flags: ensure no console window
                        nullptr,             // Use parent's environment block
                        nullptr,             // Use parent's starting directory
                        &si,                 // Pointer to STARTUPINFO structure
                        &pi))                // Pointer to PROCESS_INFORMATION structure
    {
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"CreateProcessW", cmd_line_utf16);
    }

    hProcess = pi.hProcess;    // Save for DEFER
    hThread = pi.hThread;      // Save for DEFER

    // Close handles to the child process and its primary thread that we don't need.
    CloseHandle(hThread);
    hThread = INVALID_HANDLE_VALUE;

    // Close the read end of the pipe in the parent process.
    // The child process has its own copy of this handle (hStdInRead from si.hStdInput).
    CloseHandle(hStdInRead);
    hStdInRead = INVALID_HANDLE_VALUE;

    // Write data to the pipe that is the standard input for a child process.
    if (!stdin_data.empty())
    {
        DWORD bytesWrittenTotal = 0;
        const char* pCurrentData = stdin_data.data();
        SIZE_T remainingDataSize = stdin_data.size();

        while (remainingDataSize > 0)
        {
            DWORD bytesToWriteThisCall = (remainingDataSize > MAX_SINGLE_BLOCK)
                ? MAX_SINGLE_BLOCK
                : static_cast<DWORD>(remainingDataSize);
            DWORD bytesActuallyWritten = 0;
            if (!WriteFile(hStdInWrite,
                           pCurrentData,
                           bytesToWriteThisCall,
                           &bytesActuallyWritten,
                           nullptr))
            {
                THROW_WINDOWS_EXCEPTION(GetLastError(), L"WriteFile to child stdin");
            }
            if (bytesActuallyWritten == 0
                && bytesToWriteThisCall > 0)    // Should not happen if WriteFile succeeds
            {
                throw WindowsException(ERROR_WRITE_FAULT,
                                       L"WriteFile to child stdin wrote 0 bytes unexpectedly");
            }
            pCurrentData += bytesActuallyWritten;
            remainingDataSize -= bytesActuallyWritten;
            bytesWrittenTotal += bytesActuallyWritten;
        }
        if (bytesWrittenTotal != stdin_data.size())
        {
            throw WindowsException(ERROR_WRITE_FAULT,
                                   L"WriteFile to child stdin did not write all data");
        }
    }

    // Close the write end of the pipe. This is important for child to see EOF.
    CloseHandle(hStdInWrite);
    hStdInWrite = INVALID_HANDLE_VALUE;

    // Wait until child process exits.
    if (WaitForSingleObject(hProcess, INFINITE) == WAIT_FAILED)
    {
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"WaitForSingleObject");
    }

    DWORD exitCode;
    if (!GetExitCodeProcess(hProcess, &exitCode))
    {
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"GetExitCodeProcess");
    }

    // hProcess will be closed by DEFER.
    // Other handles (hStdInRead, hStdInWrite, hThread) are already marked INVALID_HANDLE_VALUE.

    return static_cast<int>(exitCode);
}

class WindowsChildProcess final : public OSService::ChildProcess
{
private:
    HANDLE m_process_handle;

public:
    explicit WindowsChildProcess(HANDLE process_handle) : m_process_handle(process_handle)
    {
        if (m_process_handle == INVALID_HANDLE_VALUE || m_process_handle == nullptr)
        {
            throw WindowsException(ERROR_INVALID_HANDLE, L"WindowsChildProcess constructor");
        }
    }

    ~WindowsChildProcess() override
    {
        if (m_process_handle != INVALID_HANDLE_VALUE && m_process_handle != nullptr)
        {
            CloseHandle(m_process_handle);
        }
    }

    std::optional<int> exit_code() override;
};

std::optional<int> WindowsChildProcess::exit_code()
{
    DWORD current_exit_code;
    if (!GetExitCodeProcess(m_process_handle, &current_exit_code))
    {
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"GetExitCodeProcess");
    }

    if (current_exit_code == STILL_ACTIVE)
    {
        return {};
    }
    return static_cast<int>(current_exit_code);
}

std::unique_ptr<OSService::ChildProcess>
OSService::execute_child_process_with_data(absl::Span<const std::string_view> args,
                                           std::string_view stdin_data)
{
    if (args.empty())
    {
        throwInvalidArgumentException("Empty argument list");
    }

    std::string cmd_line_utf8;
    for (size_t i = 0; i < args.size(); ++i)
    {
        cmd_line_utf8 += win_quote_argv(args[i]);
        if (i < args.size() - 1)
        {
            cmd_line_utf8 += " ";
        }
    }
    std::wstring cmd_line_utf16 = widen_string(cmd_line_utf8);
    std::vector<wchar_t> mutable_cmd_line(cmd_line_utf16.begin(), cmd_line_utf16.end());
    mutable_cmd_line.push_back(L'\0');

    HANDLE hStdInRead = INVALID_HANDLE_VALUE;
    HANDLE hStdInWrite = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION pi{};
    pi.hProcess = INVALID_HANDLE_VALUE;
    pi.hThread = INVALID_HANDLE_VALUE;

    DEFER({
        CloseHandle(hStdInRead);
        CloseHandle(hStdInWrite);
        CloseHandle(pi.hThread);
        // Process ID is managed by the destructor of `WindowsChildProcess`.
    });

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    if (!CreatePipe(&hStdInRead, &hStdInWrite, &sa, 0))
    {
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"CreatePipe for stdin");
    }

    if (!SetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0))
    {
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"SetHandleInformation for hStdInWrite");
    }

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdInput = hStdInRead;
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessW(nullptr,
                        mutable_cmd_line.data(),
                        nullptr,
                        nullptr,
                        TRUE,
                        CREATE_NO_WINDOW,
                        nullptr,
                        nullptr,
                        &si,
                        &pi))
    {
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"CreateProcessW", cmd_line_utf16);
    }
    auto result = std::make_unique<WindowsChildProcess>(pi.hProcess);

    // Close the read end of the pipe in the parent process.
    CloseHandle(hStdInRead);
    hStdInRead = INVALID_HANDLE_VALUE;

    try
    {
        if (!stdin_data.empty())
        {
            const char* pCurrentData = stdin_data.data();
            SIZE_T remainingDataSize = stdin_data.size();

            while (remainingDataSize > 0)
            {
                DWORD bytesToWriteThisCall = (remainingDataSize > MAX_SINGLE_BLOCK)
                    ? MAX_SINGLE_BLOCK
                    : static_cast<DWORD>(remainingDataSize);
                DWORD bytesActuallyWritten = 0;
                if (!WriteFile(hStdInWrite,
                               pCurrentData,
                               bytesToWriteThisCall,
                               &bytesActuallyWritten,
                               nullptr))
                {
                    THROW_WINDOWS_EXCEPTION(GetLastError(), L"WriteFile to child stdin");
                }
                if (bytesActuallyWritten == 0 && bytesToWriteThisCall > 0)
                {
                    throw WindowsException(ERROR_WRITE_FAULT,
                                           L"WriteFile to child stdin wrote 0 bytes unexpectedly");
                }
                pCurrentData += bytesActuallyWritten;
                remainingDataSize -= bytesActuallyWritten;
            }
        }
    }
    catch (...)
    {
        TerminateProcess(pi.hProcess, 1);
        throw;
    }

    CloseHandle(hStdInWrite);
    hStdInWrite = INVALID_HANDLE_VALUE;

    return result;
}
}    // namespace securefs

#endif
