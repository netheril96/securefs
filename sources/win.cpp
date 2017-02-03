#ifdef _WIN32
#include "logger.h"
#include "platform.h"

#include <winfsp/winfsp.h>

#include <cerrno>
#include <limits>
#include <memory>
#include <mutex>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/utime.h>
#include <time.h>

#include <Windows.h>
#include <io.h>
#include <sddl.h>

static inline uint64_t convert_dword_pair(uint64_t low_part, uint64_t high_part)
{
    return low_part | (high_part << 32);
}

static void filetime_to_unix_time(const FILETIME* ft, struct fuse_timespec* out)
{
    long long ll = (static_cast<long long>(ft->dwHighDateTime) << 32)
        + static_cast<long long>(ft->dwLowDateTime) - 116444736000000000LL;
    static const long long FACTOR = 10000000LL;
    out->tv_sec = ll / FACTOR;
    out->tv_nsec = (ll % FACTOR) * 100;
}

static FILETIME unix_time_to_filetime(const fuse_timespec* t)
{
    long long ll = t->tv_sec * 10000000LL + t->tv_nsec / 100LL + 116444736000000000LL;
    FILETIME res;
    res.dwLowDateTime = (DWORD)ll;
    res.dwHighDateTime = (DWORD)(ll >> 32);
    return res;
}

static const DWORD MAX_SINGLE_BLOCK = std::numeric_limits<DWORD>::max();

namespace securefs
{
class WindowsException : public SystemException
{
private:
    DWORD err;
    const char* exp;

public:
    explicit WindowsException(DWORD err, const char* exp) : err(err), exp(exp) {}
    const char* type_name() const noexcept override { return "WindowsException"; }
    std::string message() const override
    {
        char buffer[2000];

        if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM,
                            nullptr,
                            err,
                            MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                            buffer,
                            sizeof(buffer),
                            nullptr))
            return strprintf("error %lu (%s)", err, exp);
        return strprintf("error %lu (%s) %s", err, exp, buffer);
    }
    DWORD win32_code() const noexcept { return err; }
    int error_number() const noexcept override
    {
        switch (err)
        {
        case ERROR_SUCCESS:
            return 0;

        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
            return ENOENT;

        case ERROR_TOO_MANY_OPEN_FILES:
        case ERROR_TOO_MANY_MODULES:
            return ENFILE;

        case ERROR_ACCESS_DENIED:
        case ERROR_NETWORK_ACCESS_DENIED:
            return EACCES;

        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_OUTOFMEMORY:
            return ENOMEM;

        // Invalid errors
        case ERROR_INVALID_FUNCTION:
        case ERROR_INVALID_HANDLE:
        case ERROR_INVALID_BLOCK:
        case ERROR_INVALID_ACCESS:
        case ERROR_INVALID_DATA:
        case ERROR_INVALID_DRIVE:
        case ERROR_INVALID_PASSWORD:
        case ERROR_INVALID_PARAMETER:
        case ERROR_INVALID_AT_INTERRUPT_TIME:
        case ERROR_INVALID_TARGET_HANDLE:
        case ERROR_INVALID_CATEGORY:
        case ERROR_INVALID_VERIFY_SWITCH:
        case ERROR_INVALID_NAME:
        case ERROR_INVALID_LEVEL:
        case ERROR_INVALID_EVENT_COUNT:
        case ERROR_INVALID_LIST_FORMAT:
        case ERROR_INVALID_SEGMENT_NUMBER:
        case ERROR_INVALID_ORDINAL:
        case ERROR_INVALID_FLAG_NUMBER:
        case ERROR_INVALID_STARTING_CODESEG:
        case ERROR_INVALID_STACKSEG:
        case ERROR_INVALID_MODULETYPE:
        case ERROR_INVALID_EXE_SIGNATURE:
        case ERROR_INVALID_MINALLOCSIZE:
        case ERROR_INVALID_SEGDPL:
        case ERROR_INVALID_SIGNAL_NUMBER:
        case ERROR_INVALID_EA_NAME:
        case ERROR_INVALID_EA_HANDLE:
        case ERROR_INVALID_OPLOCK_PROTOCOL:
        case ERROR_INVALID_LOCK_RANGE:
        case ERROR_INVALID_EXCEPTION_HANDLER:
        case ERROR_INVALID_TOKEN:
        case ERROR_INVALID_CAP:
        case ERROR_INVALID_FIELD_IN_PARAMETER_LIST:
        case ERROR_INVALID_KERNEL_INFO_VERSION:
        case ERROR_INVALID_PEP_INFO_VERSION:
        case ERROR_INVALID_ADDRESS:
        case ERROR_INVALID_UNWIND_TARGET:
        case ERROR_INVALID_PORT_ATTRIBUTES:
        case ERROR_INVALID_QUOTA_LOWER:
        case ERROR_INVALID_LDT_SIZE:
        case ERROR_INVALID_LDT_OFFSET:
        case ERROR_INVALID_LDT_DESCRIPTOR:
        case ERROR_INVALID_IMAGE_HASH:
        case ERROR_INVALID_VARIANT:
        case ERROR_INVALID_HW_PROFILE:
        case ERROR_INVALID_PLUGPLAY_DEVICE_PATH:
        case ERROR_INVALID_DEVICE_OBJECT_PARAMETER:
        case ERROR_INVALID_ACE_CONDITION:
        case ERROR_INVALID_MESSAGE:
        case ERROR_INVALID_FLAGS:
        case ERROR_INVALID_SERVICE_CONTROL:
        case ERROR_INVALID_SERVICE_ACCOUNT:
        case ERROR_INVALID_SERVICE_LOCK:
        case ERROR_INVALID_BLOCK_LENGTH:
        case ERROR_INVALID_DLL:
        case ERROR_INVALID_GROUPNAME:
        case ERROR_INVALID_COMPUTERNAME:
        case ERROR_INVALID_EVENTNAME:
        case ERROR_INVALID_DOMAINNAME:
        case ERROR_INVALID_SERVICENAME:
        case ERROR_INVALID_NETNAME:
        case ERROR_INVALID_SHARENAME:
        case ERROR_INVALID_PASSWORDNAME:
        case ERROR_INVALID_MESSAGENAME:
        case ERROR_INVALID_MESSAGEDEST:
        case ERROR_INVALID_IMPORT_OF_NON_DLL:
        case ERROR_INVALID_CRUNTIME_PARAMETER:
        case ERROR_INVALID_LABEL:
        case ERROR_INVALID_OWNER:
        case ERROR_INVALID_PRIMARY_GROUP:
        case ERROR_INVALID_ACCOUNT_NAME:
        case ERROR_INVALID_LOGON_HOURS:
        case ERROR_INVALID_WORKSTATION:
        case ERROR_INVALID_SUB_AUTHORITY:
        case ERROR_INVALID_ACL:
        case ERROR_INVALID_SID:
        case ERROR_INVALID_SECURITY_DESCR:
        case ERROR_INVALID_ID_AUTHORITY:
        case ERROR_INVALID_GROUP_ATTRIBUTES:
        case ERROR_INVALID_SERVER_STATE:
        case ERROR_INVALID_DOMAIN_STATE:
        case ERROR_INVALID_DOMAIN_ROLE:
        case ERROR_INVALID_LOGON_TYPE:
        case ERROR_INVALID_MEMBER:
        case ERROR_INVALID_WINDOW_HANDLE:
        case ERROR_INVALID_MENU_HANDLE:
        case ERROR_INVALID_CURSOR_HANDLE:
        case ERROR_INVALID_ACCEL_HANDLE:
        case ERROR_INVALID_HOOK_HANDLE:
        case ERROR_INVALID_DWP_HANDLE:
        case ERROR_INVALID_INDEX:
        case ERROR_INVALID_ICON_HANDLE:
        case ERROR_INVALID_COMBOBOX_MESSAGE:
        case ERROR_INVALID_EDIT_HEIGHT:
        case ERROR_INVALID_HOOK_FILTER:
        case ERROR_INVALID_FILTER_PROC:
        case ERROR_INVALID_LB_MESSAGE:
        case ERROR_INVALID_MSGBOX_STYLE:
        case ERROR_INVALID_SPI_VALUE:
        case ERROR_INVALID_GW_COMMAND:
        case ERROR_INVALID_THREAD_ID:
        case ERROR_INVALID_SCROLLBAR_RANGE:
        case ERROR_INVALID_SHOWWIN_COMMAND:
        case ERROR_INVALID_KEYBOARD_HANDLE:
        case ERROR_INVALID_MONITOR_HANDLE:
        case ERROR_INVALID_TASK_NAME:
        case ERROR_INVALID_TASK_INDEX:
        case ERROR_INVALID_HANDLE_STATE:
        case ERROR_INVALID_FIELD:
        case ERROR_INVALID_TABLE:
        case ERROR_INVALID_COMMAND_LINE:
        case ERROR_INVALID_PATCH_XML:
        case ERROR_INVALID_USER_BUFFER:
        case ERROR_INVALID_SEPARATOR_FILE:
        case ERROR_INVALID_PRIORITY:
        case ERROR_INVALID_PRINTER_NAME:
        case ERROR_INVALID_PRINTER_COMMAND:
        case ERROR_INVALID_DATATYPE:
        case ERROR_INVALID_ENVIRONMENT:
        case ERROR_INVALID_TIME:
        case ERROR_INVALID_FORM_NAME:
        case ERROR_INVALID_FORM_SIZE:
        case ERROR_INVALID_PRINTER_STATE:
        case ERROR_INVALID_PIXEL_FORMAT:
        case ERROR_INVALID_WINDOW_STYLE:
        case ERROR_INVALID_CMM:
        case ERROR_INVALID_PROFILE:
        case ERROR_INVALID_COLORSPACE:
        case ERROR_INVALID_TRANSFORM:
        case ERROR_INVALID_COLORINDEX:
        case ERROR_INVALID_PRINT_MONITOR:
        case ERROR_INVALID_PRINTER_DRIVER_MANIFEST:
        case ERROR_INVALID_PACKAGE_SID_LENGTH:
        case ERROR_INVALID_MEDIA:
        case ERROR_INVALID_LIBRARY:
        case ERROR_INVALID_MEDIA_POOL:
        case ERROR_INVALID_CLEANER:
        case ERROR_INVALID_OPERATION:
        case ERROR_INVALID_DRIVE_OBJECT:
        case ERROR_INVALID_REPARSE_DATA:
        case ERROR_INVALID_STATE:
        case ERROR_INVALID_OPERATION_ON_QUORUM:
        case ERROR_INVALID_CLUSTER_IPV6_ADDRESS:
        case ERROR_INVALID_TRANSACTION:
        case ERROR_INVALID_USER_PRINCIPAL_NAME:
        case ERROR_INVALID_RUNLEVEL_SETTING:
        case ERROR_INVALID_STAGED_SIGNATURE:
            return EINVAL;
        // End of invalid errors

        case ERROR_WRITE_PROTECT:
            return EROFS;

        case ERROR_NOT_READY:
        case ERROR_GEN_FAILURE:
        case ERROR_DEV_NOT_EXIST:
            return EXDEV;

        case ERROR_READ_FAULT:
        case ERROR_WRITE_FAULT:
            return EIO;

        case ERROR_LOCK_VIOLATION:
        case ERROR_LOCKED:
            return EWOULDBLOCK;

        case ERROR_HANDLE_DISK_FULL:
        case ERROR_NO_SPOOL_SPACE:
        case ERROR_DISK_FULL:
            return ENOSPC;

        case ERROR_NOT_SUPPORTED:
        case ERROR_CALL_NOT_IMPLEMENTED:
            return ENOTSUP;

        case ERROR_FILE_EXISTS:
        case ERROR_ALREADY_EXISTS:
            return EEXIST;

        case ERROR_BUFFER_OVERFLOW:
        case ERROR_LABEL_TOO_LONG:
            return ENAMETOOLONG;

        case ERROR_INSUFFICIENT_BUFFER:
            return ERANGE;

        case ERROR_DIR_NOT_EMPTY:
            return ENOTEMPTY;

        case ERROR_PATH_BUSY:
        case ERROR_BUSY:
            return EBUSY;

        case ERROR_BAD_ARGUMENTS:
        case ERROR_BAD_PATHNAME:
            return EINVAL;

        case ERROR_FILE_TOO_LARGE:
            return E2BIG;

        case ERROR_OPERATION_IN_PROGRESS:
            return EALREADY;
        }
        return EPERM;
    }
};

[[noreturn]] void throwWindowsException(DWORD err, const char* exp)
{
    if (err != 0)
        throw WindowsException(err, exp);
}

#define CHECK_CALL(exp)                                                                            \
    if (!(exp))                                                                                    \
        throwWindowsException(GetLastError(), #exp);

static void stat_file_handle(HANDLE hd, struct fuse_stat* st)
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
    st->st_gid = st->st_uid;
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        st->st_mode = S_IFDIR | 0777;
    else
        st->st_mode = S_IFREG | 0777;
    st->st_dev = info.dwVolumeSerialNumber;
    st->st_ino = convert_dword_pair(info.nFileIndexLow, info.nFileIndexHigh);
    st->st_size = convert_dword_pair(info.nFileSizeLow, info.nFileSizeHigh);
    st->st_blksize = 4096;
    st->st_blocks = (st->st_size + 4095) / 4096 * (4096 / 512);
}

class WindowsFileStream : public FileStream
{
private:
    HANDLE m_handle;

public:
    explicit WindowsFileStream(WideStringRef path, int flags, unsigned mode)
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
                               FILE_ATTRIBUTE_NORMAL,
                               nullptr);
        if (m_handle == INVALID_HANDLE_VALUE)
            throwWindowsException(GetLastError(), "CreateFile");
    }

    ~WindowsFileStream() { CloseHandle(m_handle); }

    void lock() override
    {
        OVERLAPPED o;
        memset(&o, 0, sizeof(o));
        CHECK_CALL(LockFileEx(m_handle,
                              LOCKFILE_EXCLUSIVE_LOCK,
                              0,
                              std::numeric_limits<DWORD>::max(),
                              std::numeric_limits<DWORD>::max(),
                              &o));
    }

    void unlock() override
    {
        OVERLAPPED o;
        memset(&o, 0, sizeof(o));
        CHECK_CALL(UnlockFileEx(
            m_handle, 0, std::numeric_limits<DWORD>::max(), std::numeric_limits<DWORD>::max(), &o));
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
            throwWindowsException(err, "ReadFile");
        }
        return readlen;
    }

    void close() noexcept override
    {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }

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

    length_type size() const override
    {
        _LARGE_INTEGER SIZE;
        CHECK_CALL(GetFileSizeEx(m_handle, &SIZE));
        return SIZE.QuadPart;
    }

    void flush() override {}

    void resize(length_type len) override
    {
        auto sz = size();
        if (len > sz)
        {
            std::vector<byte> zeros(len - sz);
            write(zeros.data(), sz, len - sz);
        }
        else if (len < sz)
        {
            LARGE_INTEGER llen;
            llen.QuadPart = len;
            CHECK_CALL(SetFilePointerEx(m_handle, llen, nullptr, FILE_BEGIN));
            CHECK_CALL(SetEndOfFile(m_handle));
        }
    }

    length_type optimal_block_size() const noexcept override { return 4096; }

    void fsync() override { CHECK_CALL(FlushFileBuffers(m_handle)); }
    void utimens(const struct fuse_timespec ts[2]) override
    {
        FILETIME access_time, mod_time;
        if (!ts)
        {
            GetSystemTimeAsFileTime(&access_time);
            mod_time = access_time;
        }
        else
        {
            access_time = unix_time_to_filetime(ts + 0);
            mod_time = unix_time_to_filetime(ts + 1);
        }
        CHECK_CALL(SetFileTime(m_handle, nullptr, &access_time, &mod_time));
    }
    void fstat(struct fuse_stat* st) override { stat_file_handle(m_handle, st); }
};

OSService::OSService() {}

OSService::~OSService() {}

std::wstring OSService::norm_path(StringRef path) const
{
    if (m_dir_name.empty() || path.empty()
        || (path.size() > 0 && (path[0] == '/' || path[0] == '\\'))
        || (path.size() > 2 && path[1] == ':'))
        return widen_string(path);
    else
    {
        auto str = m_dir_name + widen_string(path);
        for (wchar_t& c : str)
        {
            if (c == L'/')
                c = L'\\';
        }
        return str;
    }
}

OSService::OSService(StringRef path) : m_dir_name(widen_string(path) + L"\\") {}

std::shared_ptr<FileStream>
OSService::open_file_stream(StringRef path, int flags, unsigned mode) const
{
    return std::make_shared<WindowsFileStream>(norm_path(path), flags, mode);
}

void OSService::remove_file(StringRef path) const
{
    CHECK_CALL(DeleteFileW(norm_path(path).c_str()));
}

void OSService::remove_directory(StringRef path) const
{
    CHECK_CALL(RemoveDirectoryW(norm_path(path).c_str()));
}

void OSService::lock() const
{
    fprintf(stderr,
            "Warning: Windows does not support directory locking. "
            "Be careful not to mount the same data directory multiple times!\n");
}

void OSService::mkdir(StringRef path, unsigned mode) const
{
    if (CreateDirectoryW(norm_path(path).c_str(), nullptr) == 0)
    {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS)
            throwWindowsException(err, "CreateDirectory");
    }
}

void OSService::statfs(struct fuse_statvfs* fs_info) const
{
    memset(fs_info, 0, sizeof(*fs_info));
    ULARGE_INTEGER FreeBytesAvailable, TotalNumberOfBytes, TotalNumberOfFreeBytes;
    if (GetDiskFreeSpaceExW(
            m_dir_name.c_str(), &FreeBytesAvailable, &TotalNumberOfBytes, &TotalNumberOfFreeBytes)
        == 0)
        throwWindowsException(GetLastError(), "GetDiskFreeSpaceEx");
    auto maximum = static_cast<unsigned>(-1);
    fs_info->f_bsize = 4096;
    fs_info->f_frsize = fs_info->f_bsize;
    fs_info->f_bfree = TotalNumberOfFreeBytes.QuadPart / fs_info->f_bsize;
    fs_info->f_blocks = TotalNumberOfBytes.QuadPart / fs_info->f_bsize;
    fs_info->f_bavail = FreeBytesAvailable.QuadPart / fs_info->f_bsize;
    fs_info->f_files = maximum;
    fs_info->f_ffree = maximum;
    fs_info->f_favail = maximum;
    fs_info->f_namemax = 255;
}

void OSService::utimens(StringRef path, const fuse_timespec ts[2]) const
{
    ::__utimbuf64 buf;
    if (!ts)
    {
        buf.actime = _time64(nullptr);
        buf.modtime = buf.actime;
    }
    else
    {
        buf.actime = ts[0].tv_sec;
        buf.modtime = ts[1].tv_sec;
    }
    int rc = ::_wutime64(norm_path(path).c_str(), &buf);
    if (rc < 0)
        throwPOSIXException(errno, "_wutime64");
}

bool OSService::stat(StringRef path, struct fuse_stat* stat) const
{
    HANDLE handle = CreateFileW(norm_path(path).c_str(),
                                GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS,
                                nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_NOT_FOUND)
            return false;
        throwWindowsException(err, "CreateFileW");
    }

    DEFER(CloseHandle(handle));
    stat_file_handle(handle, stat);
    return true;
}

void OSService::link(StringRef source, StringRef dest) const { throwVFSException(ENOSYS); }
void OSService::chmod(StringRef path, fuse_mode_t mode) const
{
    int rc = ::_wchmod(norm_path(path).c_str(), mode);
    if (rc < 0)
        throwPOSIXException(errno, "_wchmod");
}

ssize_t OSService::readlink(StringRef path, char* output, size_t size) const
{
    throwVFSException(ENOSYS);
}
void OSService::symlink(StringRef source, StringRef dest) const { throwVFSException(ENOSYS); }

void OSService::rename(StringRef a, StringRef b) const
{
    auto wa = norm_path(a);
    auto wb = norm_path(b);
    DeleteFileW(wb.c_str());
    CHECK_CALL(MoveFileW(wa.c_str(), wb.c_str()));
}

int OSService::raise_fd_limit()
{
    return 65535;
    // The handle limit on Windows is high enough that no adjustments are necessary
}

// void OSService::recursive_traverse(StringRef dir,
//                                   const recursive_traverse_callback& callback) const
//{
//    struct Finder
//    {
//        HANDLE handle;
//
//        explicit Finder(HANDLE h) : handle(h) {}
//        ~Finder()
//        {
//            if (handle != INVALID_HANDLE_VALUE)
//                FindClose(handle);
//        }
//    };
//
//    WIN32_FIND_DATAA data;
//    auto find_pattern = norm_path(dir) + "\\*";
//    Finder finder(FindFirstFileA(find_pattern.c_str(), &data));
//
//    if (finder.handle == INVALID_HANDLE_VALUE)
//        throwWindowsException(GetLastError(), "FindFirstFile on pattern " + find_pattern);
//
//    do
//    {
//        if (strcmp(data.cFileName, ".") == 0 || strcmp(data.cFileName, "..") == 0)
//            continue;
//        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
//        {
//            recursive_traverse(dir + '\\' + data.cFileName, callback);
//        }
//        else
//        {
//            if (!callback(dir, data.cFileName))
//                return;
//        }
//    } while (FindNextFileA(finder.handle, &data));
//
//    if (GetLastError() != ERROR_NO_MORE_FILES)
//        throwWindowsException(GetLastError(), "FindNextFile");
//}

class WindowsDirectoryTraverser : public DirectoryTraverser
{
private:
    HANDLE m_handle;
    WIN32_FIND_DATAW m_data;

public:
    explicit WindowsDirectoryTraverser(WideStringRef pattern)
    {
        m_handle = FindFirstFileW(pattern.c_str(), &m_data);
        if (m_handle == INVALID_HANDLE_VALUE)
        {
            throwWindowsException(GetLastError(), "FindFirstFileW");
        }
    }

    ~WindowsDirectoryTraverser()
    {
        if (m_handle != INVALID_HANDLE_VALUE)
            FindClose(m_handle);
    }

    bool next(std::string* name, fuse_mode_t* type) override
    {
        while (wcscmp(m_data.cFileName, L".") == 0 || wcscmp(m_data.cFileName, L"..") == 0)
        {
            if (!FindNextFileW(m_handle, &m_data))
            {
                DWORD err = GetLastError();
                if (err == ERROR_NO_MORE_FILES)
                    return false;
                throwWindowsException(err, "FindNextFileW");
            }
        }

        if (name)
            *name = narrow_string(m_data.cFileName);
        if (type)
        {
            if (m_data.dwFileAttributes == FILE_ATTRIBUTE_NORMAL)
                *type = S_IFREG;
            else if (m_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                *type = S_IFDIR;
            else
                *type = 0;
        }
        m_data.cFileName[0] = L'.';
        m_data.cFileName[1] = 0;
        return true;
    }
};

std::unique_ptr<DirectoryTraverser> OSService::create_traverser(StringRef dir) const
{
    return securefs::make_unique<WindowsDirectoryTraverser>(norm_path(dir) + L"\\*");
}

static thread_local uint32_t cached_uid = 0;

uint32_t OSService::getuid()
{
    if (cached_uid > 0)
        return static_cast<uint32_t>(cached_uid);

    HANDLE token;
    CHECK_CALL(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    DEFER(CloseHandle(token));

    DWORD outsize = 1;
    TOKEN_USER* tkuser = nullptr;
    DEFER(free(tkuser));
    GetTokenInformation(token, TokenUser, nullptr, 0, &outsize);
    tkuser = (TOKEN_USER*)malloc(outsize);
    CHECK_CALL(GetTokenInformation(token, TokenUser, tkuser, outsize, &outsize));
    NTSTATUS rc = FspPosixMapSidToUid(tkuser->User.Sid, &cached_uid);
    if (rc)
        global_logger->warn("FspPosixMapSidToUid returns NTSTATUS %d", (int)rc);
    return cached_uid;
}

uint32_t OSService::getgid() { return getuid(); }

bool OSService::isatty(int fd) noexcept { return ::_isatty(fd) != 0; }

void OSService::get_current_time(fuse_timespec& current_time)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    filetime_to_unix_time(&ft, &current_time);
}
}

#endif
