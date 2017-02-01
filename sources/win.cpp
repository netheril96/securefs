#ifdef _WIN32
#include "platform.h"

#include <cerrno>
#include <limits>
#include <memory>
#include <mutex>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <Windows.h>
#include <io.h>
#include <sddl.h>

static void filetime_to_unix_time(const FILETIME* ft, struct timespec* out)
{
    long long ll = (static_cast<long long>(ft->dwHighDateTime) << 32)
        + static_cast<long long>(ft->dwLowDateTime) - 116444736000000000LL;
    static const long long FACTOR = 10000000LL;
    out->tv_sec = ll / FACTOR;
    out->tv_nsec = (ll % FACTOR) * 100;
}

static FILETIME unix_time_to_filetime(const timespec* t)
{
    long long ll = t->tv_sec * 10000000LL + t->tv_nsec / 100LL + 116444736000000000LL;
    FILETIME res;
    res.dwLowDateTime = (DWORD)ll;
    res.dwHighDateTime = (DWORD)(ll >> 32);
    return res;
}

static const DWORD MAX_SINGLE_BLOCK = std::numeric_limits<DWORD>::max();

static const int CONSOLE_CP_CHANGED = []() { return SetConsoleOutputCP(CP_UTF8); }();

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
        const int WIDE_BUFSIZE = 1000;
        wchar_t wide_buffer[WIDE_BUFSIZE];
        char buffer[WIDE_BUFSIZE * 2];

        if (!FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM, nullptr, err, 0, wide_buffer, WIDE_BUFSIZE, nullptr)
            || !WideCharToMultiByte(
                   CP_UTF8, 0, wide_buffer, -1, buffer, WIDE_BUFSIZE * 2, nullptr, nullptr))
            return strprintf("error %lu (%s)", err, exp);
        return strprintf("error %lu (%s) %s", err, exp, buffer);
    }
};

[[noreturn]] void throwWindowsException(DWORD err, const char* exp)
{
    throw WindowsException(err, exp);
}

#define CHECK_CALL(exp)                                                                            \
    if (!(exp))                                                                                    \
        throwWindowsException(GetLastError(), #exp);

class WindowsFileStream : public FileStream
{
private:
    std::mutex m_mutex;
    HANDLE m_handle;

public:
    explicit WindowsFileStream(WideStringRef path, int flags, unsigned mode)
    {
        DWORD access_flags = GENERIC_READ;
        if (flags & O_WRONLY)
            access_flags = GENERIC_WRITE;
        if (flags & O_RDWR)
            access_flags = GENERIC_READ | GENERIC_WRITE;

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
                               FILE_SHARE_READ | FILE_SHARE_DELETE,
                               nullptr,
                               create_flags,
                               FILE_ATTRIBUTE_NORMAL,
                               nullptr);
        if (m_handle == INVALID_HANDLE_VALUE)
            throwWindowsException(GetLastError(), "CreateFile");
    }

    ~WindowsFileStream() { CloseHandle(m_handle); }

    void lock() override { m_mutex.lock(); }

    void unlock() override { m_mutex.unlock(); }

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
    void utimens(const struct timespec ts[2]) override
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
    void fstat(FUSE_STAT* st) override
    {
        memset(st, 0, sizeof(*st));
        BY_HANDLE_FILE_INFORMATION info;
        CHECK_CALL(GetFileInformationByHandle(m_handle, &info));
        filetime_to_unix_time(&info.ftLastAccessTime, &st->st_atim);
        filetime_to_unix_time(&info.ftLastWriteTime, &st->st_mtim);
        filetime_to_unix_time(&info.ftCreationTime, &st->st_birthtim);
        st->st_ctim = st->st_mtim;

        st->st_nlink = 1;
        st->st_mode = 0644;
        st->st_size = size();
        st->st_blksize = 4096;
        st->st_blocks = (st->st_size + 4095) / 4096 * (4096 / 512);
    }
};

class OSService::Impl
{
public:
    std::wstring dir_name;

    std::wstring norm_path(StringRef path) const
    {
        if (dir_name.empty() || path.empty()
            || (path.size() > 0 && (path[0] == '/' || path[0] == '\\'))
            || (path.size() > 2 && path[1] == ':'))
            return widen_string(path);
        else
        {
            return dir_name + widen_string(path);
        }
    }
};

OSService::OSService() : impl(new Impl()) {}

OSService::~OSService() {}

OSService::OSService(StringRef path) : impl(new Impl())
{
    wchar_t resolved[8000];
    CHECK_CALL(GetFullPathNameW(widen_string(path).c_str(), 8000, resolved, nullptr));
    WideStringRef refresolved(resolved);
    if (refresolved.starts_with(L"\\\\?\\"))
        impl->dir_name = refresolved + L"\\";
    else
        impl->dir_name = L"\\\\?\\" + refresolved + L"\\";
}

std::shared_ptr<FileStream>
OSService::open_file_stream(StringRef path, int flags, unsigned mode) const
{
    return std::make_shared<WindowsFileStream>(impl->norm_path(path), flags, mode);
}

void OSService::remove_file(StringRef path) const
{
    CHECK_CALL(DeleteFileW(impl->norm_path(path).c_str()));
}

void OSService::remove_directory(StringRef path) const
{
    CHECK_CALL(RemoveDirectoryW(impl->norm_path(path).c_str()));
}

void OSService::lock() const
{
    fprintf(stderr,
            "Warning: Windows does not support directory locking. "
            "Be careful not to mount the same data directory multiple times!\n");
}

void OSService::mkdir(StringRef path, unsigned mode) const
{
    if (CreateDirectoryW(impl->norm_path(path).c_str(), nullptr) == 0)
    {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS)
            throwWindowsException(err, "CreateDirectory");
    }
}

void OSService::statfs(struct statvfs* fs_info) const
{
    memset(fs_info, 0, sizeof(*fs_info));
    ULARGE_INTEGER FreeBytesAvailable, TotalNumberOfBytes, TotalNumberOfFreeBytes;
    if (GetDiskFreeSpaceExW(impl->dir_name.c_str(),
                            &FreeBytesAvailable,
                            &TotalNumberOfBytes,
                            &TotalNumberOfFreeBytes)
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

void OSService::rename(StringRef a, StringRef b) const
{
    auto wa = impl->norm_path(a);
    auto wb = impl->norm_path(b);
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
//    auto find_pattern = impl->norm_path(dir) + "\\*";
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

uint32_t OSService::getuid() noexcept { return 0; }

uint32_t OSService::getgid() noexcept { return 0; }

bool OSService::isatty(int fd) noexcept { return ::_isatty(fd) != 0; }

void OSService::get_current_time(timespec& current_time)
{
#ifdef HAS_CLOCK_GETTIME
    clock_gettime(CLOCK_REALTIME, &current_time);
#else
    timespec_get(&current_time, TIME_UTC);
#endif
}
}

#endif
