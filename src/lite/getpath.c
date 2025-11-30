#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

#if defined(__linux__)
#include <stdio.h>
#include <unistd.h>

int securefs_get_full_path(int fd, char* path, size_t size)
{
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    ssize_t ret = readlink(proc_path, path, size > 0 ? size - 1 : 0);
    if (ret < 0)
    {
        return errno;
    }
    if ((size_t)ret >= size)
    {
        // The path was truncated
        return ENAMETOOLONG;
    }
    path[ret] = '\0';
    return 0;
}

#elif defined(__APPLE__)

#include <sys/param.h>

int securefs_get_full_path(int fd, char* path, size_t size)
{
    if (size <= MAXPATHLEN)
    {
        return ENAMETOOLONG;
    }
    if (fcntl(fd, F_GETPATH, path) == -1)
    {
        return errno;
    }
    return 0;
}

#elif defined(__FreeBSD__)
#include <sys/sysctl.h>
#include <sys/user.h>
#include <string.h>

int securefs_get_full_path(int fd, char* path, size_t size)
{
    struct kinfo_file kf;
    memset(&kf, 0, sizeof(kf));
    kf.kf_structsize = sizeof(kf);
    if (fcntl(fd, F_KINFO, &kf) == -1)
    {
        return errno;
    }
    strncpy(path, kf.kf_path, size);
    if (size > 0) {
        path[size - 1] = '\0';
    }
    return 0;
}
#endif
