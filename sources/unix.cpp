#include "myutils.h"
#include <cerrno>
#include <fuse.h>
#ifndef _WIN32
#define _DARWIN_BETTER_REALPATH 1
#include "exceptions.h"
#include "lock_enabled.h"
#include "logger.h"
#include "platform.h"

#include <absl/strings/match.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>

#include <cxxabi.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <spawn.h>
#include <sys/wait.h>
#include <typeinfo>
#include <unistd.h>

#if __has_include(<sys/xattr.h>)
#include <sys/xattr.h>
#endif

#include <signal.h>

extern char** environ;

namespace securefs
{
class UnixFileStream final : public FileStream
{
private:
    int m_fd;

public:
    explicit UnixFileStream(int fd) : m_fd(fd)
    {
        if (fd < 0)
            throwVFSException(EBADF);
    }

    ~UnixFileStream() { this->close(); }

    void close() noexcept override
    {
        ::close(m_fd);
        m_fd = -1;
    }

    void lock(bool exclusive) override
    {
        if (!securefs::is_lock_enabled())
        {
            return;
        }
        int rc = ::flock(m_fd, exclusive ? LOCK_EX : LOCK_SH);
        if (rc < 0)
        {
            THROW_POSIX_EXCEPTION(errno, "flock");
        }
    }

    void unlock() noexcept override
    {
        if (!securefs::is_lock_enabled())
        {
            return;
        }
        int rc = ::flock(m_fd, LOCK_UN);
        (void)rc;
    }

    void fsync() override
    {
        int rc = ::fsync(m_fd);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fsync");
    }

    void fstat(struct stat* out) const override
    {
        if (!out)
            throwVFSException(EFAULT);

        if (::fstat(m_fd, out) < 0)
            THROW_POSIX_EXCEPTION(errno, "fstat");
    }

    length_type read(void* output, offset_type offset, length_type length) override
    {
        auto rc = ::pread(m_fd, output, length, offset);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "pread");
        return static_cast<length_type>(rc);
    }

    length_type sequential_read(void* output, length_type length) override
    {
        auto rc = ::read(m_fd, output, length);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "read");
        return static_cast<length_type>(rc);
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        auto rc = ::pwrite(m_fd, input, length, offset);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "pwrite");
        if (static_cast<length_type>(rc) != length)
            throwVFSException(EIO);
    }

    void sequential_write(const void* input, length_type length) override
    {
        auto rc = ::write(m_fd, input, length);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "write");
        if (static_cast<length_type>(rc) != length)
            throwVFSException(EIO);
    }

    void flush() override {}

    void resize(length_type new_length) override
    {
        auto rc = ::ftruncate(m_fd, new_length);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "truncate");
    }

    length_type size() const override
    {
        struct stat st;
        this->fstat(&st);
        return static_cast<length_type>(st.st_size);
    }

    bool is_sparse() const noexcept override { return true; }

    void utimens(const fuse_timespec ts[2]) override
    {
        int rc = ::futimens(m_fd, ts);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "utimens");
    }

#ifdef __APPLE__

    void removexattr(const char* name) override
    {
        auto rc = ::fremovexattr(m_fd, name, 0);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fremovexattr");
    }

    ssize_t getxattr(const char* name, void* value, size_t size) override
    {
        ssize_t rc = ::fgetxattr(m_fd, name, value, size, 0, 0);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fgetxattr");
        return rc;
    }

    ssize_t listxattr(char* buffer, size_t size) override
    {
        auto rc = ::flistxattr(m_fd, buffer, size, 0);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "flistxattr");
        return rc;
    }

    void setxattr(const char* name, void* value, size_t size, int flags) override
    {
        auto rc = ::fsetxattr(m_fd, name, value, size, 0, flags);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fsetxattr");
    }
#elif __has_include(<sys/xattr.h>)

    void removexattr(const char* name) override
    {
        auto rc = ::fremovexattr(m_fd, name);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fremovexattr");
    }

    ssize_t getxattr(const char* name, void* value, size_t size) override
    {
        ssize_t rc = ::fgetxattr(m_fd, name, value, size);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fgetxattr");
        return rc;
    }

    ssize_t listxattr(char* buffer, size_t size) override
    {
        auto rc = ::flistxattr(m_fd, buffer, size);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "flistxattr");
        return rc;
    }

    void setxattr(const char* name, void* value, size_t size, int flags) override
    {
        auto rc = ::fsetxattr(m_fd, name, value, size, flags);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fsetxattr");
    }

#endif
};

class UnixDirectoryTraverser : public DirectoryTraverser
{
private:
    DIR* m_dir;

public:
    explicit UnixDirectoryTraverser(const std::string& path)
    {
        m_dir = ::opendir(path.c_str());
        if (!m_dir)
            THROW_POSIX_EXCEPTION(errno, "opendir " + path);
    }
    ~UnixDirectoryTraverser() { ::closedir(m_dir); }

    bool next(std::string* name, fuse_stat* st) override
    {
        errno = 0;
        auto entry = ::readdir(m_dir);
        if (!entry)
        {
            if (errno)
                THROW_POSIX_EXCEPTION(errno, "readdir");
            return false;
        }
        if (st)
        {
            memset(st, 0, sizeof(*st));
            st->st_ino = entry->d_ino;
            switch (entry->d_type)
            {
            case DT_DIR:
                st->st_mode = S_IFDIR;
                break;
            case DT_LNK:
                st->st_mode = S_IFLNK;
                break;
            case DT_REG:
                st->st_mode = S_IFREG;
                break;
            default:
                st->st_mode = 0;
                break;
            }
        }
        if (name)
        {
            *name = entry->d_name;
        }
        return true;
    }

    void rewind() override { ::rewinddir(m_dir); }
};

bool OSService::is_absolute(std::string_view path) { return path.size() > 0 && path[0] == '/'; }

native_string_type OSService::concat_and_norm(std::string_view base_dir, std::string_view path)
{
    if (base_dir.empty() || is_absolute(path))
        return {path.data(), path.size()};
    if (!is_absolute(base_dir))
    {
        throwInvalidArgumentException(absl::StrCat("base_dir must be absolute, but is ", base_dir));
    }
    if (base_dir.size() > 0 && base_dir.back() == '/')
    {
        return absl::StrCat(base_dir, path);
    }
    return absl::StrCat(base_dir, "/", path);
}

OSService::OSService() { m_dir_fd = AT_FDCWD; }

OSService::~OSService()
{
    if (m_dir_fd >= 0)
        ::close(m_dir_fd);
}

OSService::OSService(const std::string& path)
{
    char buffer[PATH_MAX + 1] = {0};
    char* rc = ::realpath(path.c_str(), buffer);
    if (!rc)
        THROW_POSIX_EXCEPTION(errno, "realpath on " + path);
    m_dir_name.reserve(strlen(buffer) + 1);
    m_dir_name.assign(buffer);
    m_dir_name.push_back('/');

    int dir_fd = ::open(path.c_str(), O_RDONLY);
    if (dir_fd < 0)
        THROW_POSIX_EXCEPTION(errno, "Opening directory " + path);
    m_dir_fd = dir_fd;
}

std::shared_ptr<FileStream>
OSService::open_file_stream(const std::string& path, int flags, unsigned mode) const
{
    int fd = ::openat(m_dir_fd, path.c_str(), flags, mode);
    if (fd < 0)
        THROW_POSIX_EXCEPTION(errno,
                              absl::StrFormat("Opening %s with flags %#o", norm_path(path), flags));
    return std::make_shared<UnixFileStream>(fd);
}

void OSService::remove_file(const std::string& path) const
{
    int rc = ::unlinkat(m_dir_fd, path.c_str(), 0);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno, "unlinking " + norm_path(path));
}

void OSService::remove_directory(const std::string& path) const
{
    int rc = ::unlinkat(m_dir_fd, path.c_str(), AT_REMOVEDIR);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno, "removing directory " + norm_path(path));
}

void OSService::lock() const
{
    if (!securefs::is_lock_enabled())
    {
        return;
    }
    int rc = ::flock(m_dir_fd, LOCK_NB | LOCK_EX);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno,
                              absl::StrFormat("Fail to obtain exclusive lock on %s", m_dir_name));
}

void OSService::mkdir(const std::string& path, unsigned mode) const
{
    int rc = ::mkdirat(m_dir_fd, path.c_str(), mode);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno,
                              absl::StrFormat("Fail to create directory %s", norm_path(path)));
}

void OSService::ensure_directory(const std::string& path, unsigned mode) const
{
    int rc = ::mkdirat(m_dir_fd, path.c_str(), mode);
    if (rc < 0 && errno != EEXIST)
        THROW_POSIX_EXCEPTION(errno,
                              absl::StrFormat("Fail to create directory %s", norm_path(path)));
}

bool OSService::remove_file_nothrow(const std::string& path) const noexcept
{
    return ::unlinkat(m_dir_fd, path.c_str(), 0) == 0;
}

bool OSService::remove_directory_nothrow(const std::string& path) const noexcept
{
    return ::unlinkat(m_dir_fd, path.c_str(), AT_REMOVEDIR) == 0;
}

void OSService::symlink(const std::string& to, const std::string& from) const
{
    int rc = ::symlinkat(to.c_str(), m_dir_fd, from.c_str());
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno,
                              absl::StrFormat("symlink to=%s and from=%s", to, norm_path(from)));
}

void OSService::link(const std::string& source, const std::string& dest) const
{
    int rc = ::linkat(m_dir_fd, source.c_str(), m_dir_fd, dest.c_str(), 0);
    if (rc < 0)
    {
        THROW_POSIX_EXCEPTION(errno, absl::StrFormat("link src=%s dest=%s", source, dest));
    }
}

void OSService::statfs(fuse_statvfs* fs_info) const
{
    int rc = ::fstatvfs(m_dir_fd, fs_info);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno, "statvfs");
}

void OSService::rename(const std::string& a, const std::string& b) const
{
    int rc = ::renameat(m_dir_fd, a.c_str(), m_dir_fd, b.c_str());
    if (rc < 0)
        THROW_POSIX_EXCEPTION(
            errno, absl::StrFormat("Renaming from %s to %s", norm_path(a), norm_path(b)));
}

bool OSService::stat(const std::string& path, fuse_stat* stat) const
{
    int rc = ::fstatat(m_dir_fd, path.c_str(), stat, AT_SYMLINK_NOFOLLOW);
    if (rc < 0)
    {
        if (errno == ENOENT)
            return false;
        THROW_POSIX_EXCEPTION(errno, absl::StrFormat("stating %s", norm_path(path)));
    }
    return true;
}

void OSService::chmod(const std::string& path, fuse_mode_t mode) const
{
    int rc = ::fchmodat(m_dir_fd, path.c_str(), mode, AT_SYMLINK_NOFOLLOW);
    if (rc < 0 && errno == ENOTSUP)
        rc = ::fchmodat(m_dir_fd, path.c_str(), mode, 0);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno,
                              absl::StrFormat("chmod %s with mode=0%o", norm_path(path), mode));
}

void OSService::chown(const std::string& path, uid_t uid, gid_t gid) const
{
    int rc = ::fchownat(m_dir_fd, path.c_str(), uid, gid, AT_SYMLINK_NOFOLLOW);
    if (rc < 0 && errno == ENOTSUP)
        rc = ::fchownat(m_dir_fd, path.c_str(), uid, gid, 0);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(
            errno, absl::StrFormat("chown %s with uid=%d and gid=%d", norm_path(path), uid, gid));
}

ssize_t OSService::readlink(const std::string& path, char* output, size_t size) const
{
    ssize_t rc = ::readlinkat(m_dir_fd, path.c_str(), output, size);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(
            errno, absl::StrFormat("readlink %s with buffer size=%zu", norm_path(path), size));
    return rc;
}

void OSService::utimens(const std::string& path, const fuse_timespec* ts) const
{
    int rc = ::utimensat(m_dir_fd, path.c_str(), ts, AT_SYMLINK_NOFOLLOW);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno, "utimensat");
}

std::unique_ptr<DirectoryTraverser> OSService::create_traverser(const std::string& dir) const
{
    return securefs::make_unique<UnixDirectoryTraverser>(norm_path(dir));
}

uint32_t OSService::getuid() noexcept { return ::getuid(); }
uint32_t OSService::getgid() noexcept { return ::getgid(); }

int64_t OSService::raise_fd_limit() noexcept
{
    struct rlimit rl;
    int rc = ::getrlimit(RLIMIT_NOFILE, &rl);
    if (rc < 0)
    {
        WARN_LOG("Failed to query limit of file descriptors. Error code: %d.", errno);
        return 1024;
    }

    if (rl.rlim_cur >= rl.rlim_max)
    {
        return rl.rlim_cur;
    }

    auto current_limit = rl.rlim_cur;
    rl.rlim_cur = rl.rlim_max;
    rc = ::setrlimit(RLIMIT_NOFILE, &rl);
    if (rc < 0)
    {
        WARN_LOG("Failed to set limit of file descriptors. Error code: %d.", errno);
        return current_limit;
    }
    return rl.rlim_cur;
}

void OSService::get_current_time(fuse_timespec& current_time)
{
    clock_gettime(CLOCK_REALTIME, &current_time);
}

bool OSService::is_process_running(pid_t pid)
{
    // POSIX implementation (Linux, macOS, FreeBSD)

    // kill(pid, 0) sends no signal but checks for existence and permissions.
    // Returns 0 on success (process exists and visible).
    // Returns -1 on error.
    // If returns -1 and errno is ESRCH, the process does not exist.
    // If returns -1 and errno is EPERM, the process exists but we don't have permission
    // to signal it. For the purpose of "is it running", we consider it running.

    if (pid <= 0)
    {    // PIDs are positive; 0 means current process group, -1 means all processes
        if (pid == 0)
            return true;    // PID 0 typically means current process group
        return false;       // Invalid PID
    }

    int result = kill(pid, 0);
    if (result == 0)
    {
        // Process exists and we have permission to signal it.
        return true;
    }
    return errno != ESRCH;
}

#ifdef __APPLE__
ssize_t OSService::listxattr(const char* path, char* buf, size_t size) const noexcept
{
    auto rc = ::listxattr(norm_path(path).c_str(), buf, size, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

ssize_t
OSService::getxattr(const char* path, const char* name, void* buf, size_t size) const noexcept
{
    auto rc = ::getxattr(norm_path(path).c_str(), name, buf, size, 0, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

int OSService::setxattr(
    const char* path, const char* name, void* buf, size_t size, int flags) const noexcept
{
    auto rc = ::setxattr(norm_path(path).c_str(), name, buf, size, 0, flags | XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

int OSService::removexattr(const char* path, const char* name) const noexcept
{
    auto rc = ::removexattr(norm_path(path).c_str(), name, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}
#elif __has_include(<sys/xattr.h>)
ssize_t OSService::listxattr(const char* path, char* buf, size_t size) const noexcept
{
    auto rc = ::llistxattr(norm_path(path).c_str(), buf, size);
    return rc < 0 ? -errno : rc;
}

ssize_t
OSService::getxattr(const char* path, const char* name, void* buf, size_t size) const noexcept
{
    auto rc = ::lgetxattr(norm_path(path).c_str(), name, buf, size);
    return rc < 0 ? -errno : rc;
}

int OSService::setxattr(
    const char* path, const char* name, void* buf, size_t size, int flags) const noexcept
{
    auto rc = ::lsetxattr(norm_path(path).c_str(), name, buf, size, flags);
    return rc < 0 ? -errno : rc;
}

int OSService::removexattr(const char* path, const char* name) const noexcept
{
    auto rc = ::lremovexattr(norm_path(path).c_str(), name);
    return rc < 0 ? -errno : rc;
}
#else
ssize_t OSService::listxattr(const char* path, char* buf, size_t size) const noexcept
{
    return -ENOSYS;
}

ssize_t
OSService::getxattr(const char* path, const char* name, void* buf, size_t size) const noexcept
{
    return -ENOSYS;
}

int OSService::setxattr(
    const char* path, const char* name, void* buf, size_t size, int flags) const noexcept
{
    return -ENOSYS;
}

int OSService::removexattr(const char* path, const char* name) const noexcept { return -ENOSYS; }
#endif

unsigned OSService::get_cmd_for_query_ioctl() noexcept { return _IOR('s', 1, unsigned); }
unsigned OSService::get_cmd_for_trigger_unmount_ioctl() noexcept { return _IO('s', 2); }
bool OSService::query_if_mounted_by_ioctl() const
{
    unsigned magic = 0;
    return ioctl(m_dir_fd, get_cmd_for_query_ioctl(), &magic) == 0
        && magic == get_magic_for_mounted_status();
}
void OSService::trigger_unmount_by_ioctl() const
{
    if (ioctl(m_dir_fd, get_cmd_for_trigger_unmount_ioctl()) < 0)
    {
        THROW_POSIX_EXCEPTION(
            errno, absl::StrFormat("ioctl(%d, %d)", m_dir_fd, get_cmd_for_trigger_unmount_ioctl()));
    }
}

void OSService::read_password_no_confirmation(const char* prompt,
                                              CryptoPP::AlignedSecByteBlock* output)
{
    byte buffer[4000];
    DEFER(CryptoPP::SecureWipeBuffer(buffer, array_length(buffer)));
    size_t bufsize = 0;

    struct termios old_tios, new_tios;
    if (::isatty(STDIN_FILENO))
    {
        if (::isatty(STDERR_FILENO))
        {
            fputs(prompt, stderr);
            fflush(stderr);
        }

        tcgetattr(STDIN_FILENO, &old_tios);
        new_tios = old_tios;
        new_tios.c_lflag &= ~(unsigned)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_tios);
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
    if (::isatty(STDIN_FILENO))
    {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_tios);
        putc('\n', stderr);
    }
    output->resize(bufsize);
    memcpy(output->data(), buffer, bufsize);
}

void OSService::get_current_time_in_tm(struct tm* tm, int* nanoseconds)
{
    timespec now;
    get_current_time(now);
    if (tm)
        gmtime_r(&now.tv_sec, tm);
    if (nanoseconds)
        *nanoseconds = static_cast<int>(now.tv_nsec);
}

void OSService::read_password_with_confirmation(const char* prompt,
                                                CryptoPP::AlignedSecByteBlock* output)
{
    read_password_no_confirmation(prompt, output);
    if (!::isatty(STDIN_FILENO) || !::isatty(STDERR_FILENO))
    {
        return;
    }
    CryptoPP::AlignedSecByteBlock another;
    read_password_no_confirmation("Again: ", &another);
    if (output->size() != another.size()
        || memcmp(output->data(), another.data(), another.size()) != 0)
        throw_runtime_error("Password mismatch");
}

void OSService::enter_background() { daemon(true, false); }
pid_t OSService::get_current_process_id() { return getpid(); }

// These two overloads are used to distinguish the GNU and XSI version of strerror_r

// GNU
static std::string postprocess_strerror(const char* rc, const char* buffer, int code)
{
    if (rc)
        return rc;
    (void)buffer;
    return absl::StrFormat("Unknown POSIX error %d", code);
}

// XSI
static std::string postprocess_strerror(int rc, const char* buffer, int code)
{
    if (rc == 0)
        return buffer;
    return absl::StrFormat("Unknown POSIX error %d", code);
}

std::string OSService::stringify_system_error(int errcode)
{
    char buffer[4000];
    return postprocess_strerror(strerror_r(errcode, buffer, array_length(buffer)), buffer, errcode);
}

std::unique_ptr<ConsoleColourSetter> ConsoleColourSetter::create_setter(FILE* fp)
{
    if (!fp || !::isatty(::fileno(fp)))
        return {};
    return securefs::make_unique<POSIXColourSetter>(fp);
}

std::unique_ptr<const char, void (*)(const char*)> get_type_name(const std::exception& e) noexcept
{
    const char* name = typeid(e).name();
    const char* demangled = abi::__cxa_demangle(name, nullptr, nullptr, nullptr);
    if (demangled)
        return {demangled, [](const char* ptr) { free((void*)ptr); }};
    return {name, [](const char*) { /* no op */ }};
}

int OSService::execute_child_process_with_data_and_wait(absl::Span<const std::string_view> args,
                                                        std::string_view stdin_data)
{
    if (args.empty())
    {
        throwInvalidArgumentException("Empty argument list");
    }

    std::vector<std::string> c_argv_storage;
    c_argv_storage.reserve(args.size());
    for (const auto& sv : args)
    {
        c_argv_storage.emplace_back(sv);
    }

    std::vector<char*> c_argv_ptrs;
    c_argv_ptrs.reserve(args.size() + 1);
    for (const auto& s : c_argv_storage)
    {
        c_argv_ptrs.push_back(const_cast<char*>(s.c_str()));
    }
    c_argv_ptrs.push_back(nullptr);
    char* const* argv_for_spawn = c_argv_ptrs.data();
    const char* file_to_exec = argv_for_spawn[0];

    pid_t pid = -1;
    int pipefd[2] = {-1, -1};    // pipefd[0] is read end, pipefd[1] is write end
    posix_spawn_file_actions_t file_actions;
    bool file_actions_initialized = false;
    posix_spawnattr_t attr;
    bool attr_initialized = false;

    DEFER({
        if (pipefd[0] != -1)
            ::close(pipefd[0]);
        if (pipefd[1] != -1)
            ::close(pipefd[1]);
        if (file_actions_initialized)
            posix_spawn_file_actions_destroy(&file_actions);
        if (attr_initialized)
            posix_spawnattr_destroy(&attr);
    });

    if (::pipe(pipefd) == -1)
    {
        THROW_POSIX_EXCEPTION(errno, "pipe for stdin");
    }

    int ret;
    if ((ret = posix_spawn_file_actions_init(&file_actions)) != 0)
    {
        THROW_POSIX_EXCEPTION(ret, "posix_spawn_file_actions_init");
    }
    file_actions_initialized = true;

    if ((ret = posix_spawn_file_actions_addclose(&file_actions, pipefd[1])) != 0)
    {
        THROW_POSIX_EXCEPTION(ret, "posix_spawn_file_actions_addclose (pipe write end)");
    }
    if ((ret = posix_spawn_file_actions_adddup2(&file_actions, pipefd[0], STDIN_FILENO)) != 0)
    {
        THROW_POSIX_EXCEPTION(ret, "posix_spawn_file_actions_adddup2 (stdin)");
    }
    if ((ret = posix_spawn_file_actions_addclose(&file_actions, pipefd[0])) != 0)
    {
        THROW_POSIX_EXCEPTION(ret, "posix_spawn_file_actions_addclose (pipe read end)");
    }

    if ((ret = posix_spawnattr_init(&attr)) != 0)
    {
        THROW_POSIX_EXCEPTION(ret, "posix_spawnattr_init");
    }
    attr_initialized = true;

    short spawn_flags = 0;
#ifdef POSIX_SPAWN_SETSID
    spawn_flags |= POSIX_SPAWN_SETSID;
#else
    WARN_LOG("POSIX_SPAWN_SETSID not defined, child process will not get a new session ID via posix_spawnattr_setflags.");
#endif
    if (spawn_flags != 0)
    {
        if ((ret = posix_spawnattr_setflags(&attr, spawn_flags)) != 0)
        {
            THROW_POSIX_EXCEPTION(ret, "posix_spawnattr_setflags");
        }
    }

    ::close(pipefd[0]);
    pipefd[0] = -1;

    if ((ret = posix_spawnp(&pid, file_to_exec, &file_actions, &attr, argv_for_spawn, environ)) != 0)
    {
        THROW_POSIX_EXCEPTION(ret, absl::StrCat("posix_spawnp failed for ", file_to_exec));
    }

    if (!stdin_data.empty())
    {
        const char* current_data_ptr = stdin_data.data();
        size_t remaining_data_size = stdin_data.size();
        while (remaining_data_size > 0)
        {
            ssize_t bytes_written_this_call = ::write(pipefd[1], current_data_ptr, remaining_data_size);
            if (bytes_written_this_call < 0)
            {
                if (errno == EINTR) continue;
                THROW_POSIX_EXCEPTION(errno, "write to child stdin");
            }
            if (bytes_written_this_call == 0) { // Should not happen for blocking pipe if read end is open
                 THROW_POSIX_EXCEPTION(EPIPE, "write to child stdin wrote 0 bytes unexpectedly");
            }
            current_data_ptr += bytes_written_this_call;
            remaining_data_size -= bytes_written_this_call;
        }
    }

    ::close(pipefd[1]);
    pipefd[1] = -1;

    int status;
    if (::waitpid(pid, &status, 0) == -1)
    {
        THROW_POSIX_EXCEPTION(errno, "waitpid");
    }

    if (WIFEXITED(status))
    {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status))
    {
        return 128 + WTERMSIG(status);
    }
    return -1; // Should generally not be reached if waitpid succeeds
}

const char* PATH_SEPARATOR_STRING = "/";
const char PATH_SEPARATOR_CHAR = '/';
}    // namespace securefs
#endif
