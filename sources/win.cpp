#ifdef _WIN32
#include "platform.h"

#include <cerrno>
#include <limits>
#include <memory>
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

static const int MAX_SINGLE_BLOCK = 1 << 30;

namespace securefs
{
class WindowsException : public SeriousException
{
private:
    DWORD err;
    std::string msg;

public:
    explicit WindowsException(DWORD err, std::string msg) : err(err), msg(std::move(msg)) {}
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
            return strprintf("error %d (%s)", static_cast<int>(err), msg.c_str());
        return strprintf("error %d (%s) %s", static_cast<int>(err), msg.c_str(), buffer);
    }
};

class WindowsFileStream : public FileStream
{
private:
    HANDLE m_handle;

private:
    void seek(long long pos)
    {
        _LARGE_INTEGER POS;
        POS.QuadPart = pos;
        if (SetFilePointerEx(m_handle, POS, nullptr, FILE_BEGIN) == 0)
            throw WindowsException(GetLastError(), "SetFilePointerEx");
    }

public:
    explicit WindowsFileStream(const std::string& path, int flags, unsigned mode)
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

        m_handle = CreateFileA(path.c_str(),
                               access_flags,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr,
                               create_flags,
                               FILE_ATTRIBUTE_NORMAL,
                               nullptr);
        if (m_handle == INVALID_HANDLE_VALUE)
            throw WindowsException(GetLastError(), "CreateFile");
    }

    ~WindowsFileStream() { CloseHandle(m_handle); }

    length_type read(void* output, offset_type offset, length_type length) override
    {
        seek(offset);
        length_type total = 0;
        while (length > MAX_SINGLE_BLOCK)
        {
            DWORD cur;
            if (ReadFile(m_handle, output, static_cast<DWORD>(MAX_SINGLE_BLOCK), &cur, nullptr)
                == 0)
                throw WindowsException(GetLastError(), "ReadFile");
            if (cur == 0)
                return total;
            total += cur;
            length -= MAX_SINGLE_BLOCK;
            output = static_cast<char*>(output) + MAX_SINGLE_BLOCK;
        }

        DWORD cur;
        if (ReadFile(m_handle, output, static_cast<DWORD>(length), &cur, nullptr) == 0)
            throw WindowsException(GetLastError(), "ReadFile");
        total += cur;
        return total;
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        seek(offset);
        length_type total = 0;
        while (length > MAX_SINGLE_BLOCK)
        {
            DWORD cur;
            if (WriteFile(m_handle, input, static_cast<DWORD>(MAX_SINGLE_BLOCK), &cur, nullptr)
                == 0)
                throw WindowsException(GetLastError(), "WriteFile");
            if (cur == 0)
                throw OSException(EIO);
            total += cur;
            length -= MAX_SINGLE_BLOCK;
            input = static_cast<const char*>(input) + MAX_SINGLE_BLOCK;
        }

        DWORD cur;
        if (WriteFile(m_handle, input, static_cast<DWORD>(length), &cur, nullptr) == 0)
            throw WindowsException(GetLastError(), "WriteFile");
        total += cur;
        if (total != length)
            throw OSException(EIO);
    }

    length_type size() const override
    {
        _LARGE_INTEGER SIZE;
        if (GetFileSizeEx(m_handle, &SIZE) == 0)
            throw WindowsException(GetLastError(), "GetFileSizeEx");
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
            seek(len);
            if (SetEndOfFile(m_handle) == 0)
                throw WindowsException(GetLastError(), "SetEndOfFile");
        }
    }

    length_type optimal_block_size() const noexcept override { return 4096; }

    void fsync() override
    {
        if (FlushFileBuffers(m_handle) == 0)
            throw WindowsException(GetLastError(), "FlushFileBuffers");
    }
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
        if (SetFileTime(m_handle, nullptr, &access_time, &mod_time) == 0)
            throw WindowsException(GetLastError(), "SetFileTime");
    }
    void fstat(FUSE_STAT* st) override
    {
        memset(st, 0, sizeof(*st));
        BY_HANDLE_FILE_INFORMATION info;
        if (GetFileInformationByHandle(m_handle, &info) == 0)
            throw WindowsException(GetLastError(), "GetFileInformationByHandle");
        filetime_to_unix_time(&info.ftLastAccessTime, &st->st_atim);
        filetime_to_unix_time(&info.ftLastWriteTime, &st->st_mtim);
        filetime_to_unix_time(&info.ftCreationTime, &st->st_birthtim);
        st->st_ctim = st->st_mtim;
    }
};

class OSService::Impl
{
public:
    std::string dir_name;

    std::string norm_path(const std::string& path) const
    {
        if (dir_name.empty() || (path.size() > 0 && (path[0] == '/' || path[0] == '\\'))
            || (path.size() > 2 && path[1] == ':'))
            return path;
        else
        {
            return dir_name + '\\' + path;
        }
    }
};

OSService::OSService() : impl(new Impl()) {}

OSService::~OSService() {}

OSService::OSService(const std::string& path) : impl(new Impl()) { impl->dir_name = path; }

std::shared_ptr<FileStream>
OSService::open_file_stream(const std::string& path, int flags, unsigned mode) const
{
    return std::make_shared<WindowsFileStream>(impl->norm_path(path), flags, mode);
}

bool OSService::remove_file(const std::string& path) const noexcept
{
    return DeleteFileA(impl->norm_path(path).c_str()) != 0;
}

bool OSService::remove_directory(const std::string& path) const noexcept
{
    return RemoveDirectoryA(impl->norm_path(path).c_str()) != 0;
}

void OSService::lock() const
{
    fprintf(stderr,
            "Warning: Windows does not support directory locking. "
            "Be careful not to mount the same data directory multiple times!\n");
}

void OSService::ensure_directory(const std::string& path, unsigned mode) const
{
    if (CreateDirectoryA(impl->norm_path(path).c_str(), nullptr) == 0)
    {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS)
            throw WindowsException(err, "CreateDirectory");
    }
}

void OSService::statfs(struct statvfs* fs_info) const
{
    memset(fs_info, 0, sizeof(*fs_info));
    ULARGE_INTEGER FreeBytesAvailable, TotalNumberOfBytes, TotalNumberOfFreeBytes;
    if (GetDiskFreeSpaceExA(impl->dir_name.c_str(),
                            &FreeBytesAvailable,
                            &TotalNumberOfBytes,
                            &TotalNumberOfFreeBytes)
        == 0)
        throw WindowsException(GetLastError(), "GetDiskFreeSpaceEx");
    auto maximum = static_cast<unsigned>(-1);
    fs_info->f_bsize = 4096;
    fs_info->f_frsize = fs_info->f_bsize;
    fs_info->f_bfree = TotalNumberOfFreeBytes.QuadPart / fs_info->f_bsize;
    fs_info->f_blocks = TotalNumberOfBytes.QuadPart / fs_info->f_bsize;
    fs_info->f_bavail = FreeBytesAvailable.QuadPart / fs_info->f_bsize;
    fs_info->f_files = maximum;
    fs_info->f_ffree = maximum;
    fs_info->f_favail = maximum;
}

void OSService::rename(const std::string& a, const std::string& b) const
{
    auto wa = impl->norm_path(a);
    auto wb = impl->norm_path(b);
    DeleteFileA(wb.c_str());
    if (MoveFileA(wa.c_str(), wb.c_str()) == 0)
        throw WindowsException(GetLastError(), "MoveFile");
}

int OSService::raise_fd_limit()
{
    return 65535;
    // The handle limit on Windows is high enough that no adjustments are necessary
}

uint32_t OSService::getuid() noexcept { return 0; }

uint32_t OSService::getgid() noexcept { return 0; }

bool OSService::isatty(int fd) noexcept { return ::_isatty(fd) != 0; }

void OSService::get_current_time(timespec& current_time) { timespec_get(&current_time, TIME_UTC); }

std::string normalize_to_lower_case(const char* input)
{
    size_t len = strlen(input);
    std::vector<wchar_t> buffer(len);
    if (len > std::numeric_limits<int>::max())
        throw InvalidArgumentException("String size too large");
    int wide_count = MultiByteToWideChar(
        CP_UTF8, 0, input, static_cast<int>(len), buffer.data(), static_cast<int>(buffer.size()));
    if (wide_count == 0)
        throw WindowsException(GetLastError(), "MultiByteToWideChar");
    if (CharLowerBuffW(buffer.data(), wide_count) != wide_count)
        throw WindowsException(GetLastError(), "CharLowerBuff");
    int narrow_count
        = WideCharToMultiByte(CP_UTF8, 0, buffer.data(), wide_count, nullptr, 0, nullptr, nullptr);
    if (narrow_count == 0)
        throw WindowsException(GetLastError(), "MultiByteToWideChar");
    std::string output(narrow_count, '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, buffer.data(), wide_count, &output[0], narrow_count, nullptr, nullptr);
    return output;
}
}

#endif
