#pragma once

#include <memory>
#include <stddef.h>

struct statvfs;

namespace securefs
{
class StreamBase;

class RootDirectory
{
    DISABLE_COPY_MOVE(RootDirectory)

public:
    RootDirectory() {}
    virtual ~RootDirectory() {}
    virtual std::shared_ptr<StreamBase> open_file_stream(const char* path, int flags, unsigned mode)
        = 0;
    virtual bool remove_file(const char* path) noexcept = 0;
    virtual bool remove_directory(const char* path) noexcept = 0;
    virtual void lock() = 0;
    virtual void ensure_directory(const char* path, unsigned mode) = 0;
    virtual void statfs(struct statvfs*) = 0;
};

std::shared_ptr<RootDirectory> open_root(const char* path, bool readonly);
}