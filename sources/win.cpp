#ifdef _WIN32
#include "platform.h"

#include <cerrno>
#include <codecvt>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <Windows.h>
#include <sddl.h>

static std::string from_utf16(const std::wstring& str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(str);
}

static std::wstring from_utf8(const std::string& str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

static long long filetime_to_unix_time(const FILETIME* ft)
{
    long long ll = (long long(ft->dwHighDateTime) << 32) + ft->dwLowDateTime;
    return (ll - 116444736000000000LL) / 10000000LL;
}

static FILETIME unix_time_to_filetime(const timespec* t)
{
    long long ll = t->tv_sec * 10000000L + t->tv_nsec * 10L + 116444736000000000LL;
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
    int error_number() const noexcept override { return EPERM; }
    std::string message() const override
    {
        char buffer[256] = "UNKNOWN ERROR";

        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL,
                       err,
                       0,
                       buffer,
                       256,
                       NULL);

        return fmt::format("{}: {}", buffer, msg);
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
    explicit WindowsFileStream(const std::wstring& path, int flags, unsigned mode)
    {
        DWORD access = GENERIC_READ;
        if (flags & O_WRONLY)
            access = GENERIC_WRITE;
        if (flags & O_RDWR)
            access = GENERIC_READ | GENERIC_WRITE;

        DWORD create = 0;
        if (flags & O_CREAT)
        {
            if (flags & O_EXCL)
                create = CREATE_NEW;
            else
                create = OPEN_ALWAYS;
        }
        else if (flags & O_TRUNC)
        {
            create = TRUNCATE_EXISTING;
        }
        else
        {
            create = OPEN_EXISTING;
        }

        m_handle
            = CreateFileW(path.c_str(), access, 0, nullptr, create, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (m_handle == INVALID_HANDLE_VALUE)
            throw WindowsException(GetLastError(), "CreateFileW");
    }

    ~WindowsFileStream() { CloseHandle(m_handle); }

    length_type read(void* output, offset_type offset, length_type length) override
    {
        seek(offset);
        DWORD total = 0;
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
        DWORD total = 0;
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
        if (!ts)
            return;
        auto access_time = unix_time_to_filetime(ts + 0);
        auto mod_time = unix_time_to_filetime(ts + 1);
        if (SetFileTime(m_handle, nullptr, &access_time, &mod_time) == 0)
            throw WindowsException(GetLastError(), "SetFileTime");
    }
    void fstat(real_stat_type* st) override
    {
        memset(st, 0, sizeof(*st));
        BY_HANDLE_FILE_INFORMATION info;
        if (GetFileInformationByHandle(m_handle, &info) == 0)
            throw WindowsException(GetLastError(), "GetFileInformationByHandle");
        st->st_atim.tv_sec = filetime_to_unix_time(&info.ftLastAccessTime);
        st->st_mtim.tv_nsec = filetime_to_unix_time(&info.ftLastWriteTime);
        st->st_birthtim.tv_sec = filetime_to_unix_time(&info.ftCreationTime);
        st->st_ctim.tv_sec = filetime_to_unix_time(&info.ftLastWriteTime);
    }
};

class FileSystemServiceImpl
{
public:
    std::wstring dir_name;
};

static std::wstring full_path(FileSystemServiceImpl* impl, const std::string& path)
{
    if (impl->dir_name.empty())
        return from_utf8(path);
    auto result = impl->dir_name + L"\\" + from_utf8(path);
    for (wchar_t& c : result)
    {
        if (c == L'/')
            c = L'\\';
    }
    return result;
}

FileSystemService::FileSystemService() : impl(new Impl()) {}

FileSystemService::~FileSystemService() {}

FileSystemService::FileSystemService(const std::string& path) : impl(new Impl())
{
    impl->dir_name = L"//?/" + from_utf8(path);
}

std::shared_ptr<FileStream>
FileSystemService::open_file_stream(const std::string& path, int flags, unsigned mode)
{
    return std::make_shared<WindowsFileStream>(full_path(impl.get(), path), flags, mode);
}

bool FileSystemService::remove_file(const std::string& path) noexcept
{
    return DeleteFileW(full_path(impl.get(), path).c_str());
}

bool FileSystemService::remove_directory(const std::string& path) noexcept
{
    return RemoveDirectoryW(full_path(impl.get(), path).c_str());
}

void FileSystemService::lock() {}

void FileSystemService::ensure_directory(const std::string& path, unsigned mode)
{
    if (CreateDirectoryW(full_path(impl.get(), path).c_str(), nullptr) == 0)
    {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS)
            throw WindowsException(err, "CreateDirectoryW");
    }
}

void FileSystemService::statfs(struct statvfs* fs_info)
{
    memset(fs_info, 0, sizeof(*fs_info));
    ULARGE_INTEGER FreeBytesAvailable, TotalNumberOfBytes, TotalNumberOfFreeBytes;
    if (GetDiskFreeSpaceExW(impl->dir_name.c_str(),
                            &FreeBytesAvailable,
                            &TotalNumberOfBytes,
                            &TotalNumberOfFreeBytes)
        == 0)
        throw WindowsException(GetLastError(), "GetDiskFreeSpaceExW");
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

void FileSystemService::rename(const std::string& a, const std::string& b)
{
    auto wa = full_path(impl.get(), a);
    auto wb = full_path(impl.get(), b);
    DeleteFileW(wb.c_str());
    if (MoveFileW(wa.c_str(), wb.c_str()) == 0)
        throw WindowsException(GetLastError(), "MoveFileW");
}

bool FileSystemService::raise_fd_limit() noexcept
{
    return true;
    // The handle limit on Windows is high enough that no adjustments are necessary
}

std::string format_current_time()
{
    wchar_t buffer[256];
    if (GetTimeFormatEx(
            LOCALE_NAME_USER_DEFAULT, TIME_FORCE24HOURFORMAT, nullptr, nullptr, buffer, 256)
        == 0)
        return "UNKNOWN TIME";
    return from_utf16(buffer);
}

uint32_t FileSystemService::getuid() noexcept { return 0; }

uint32_t FileSystemService::getgid() noexcept { return 0; }
}
#endif