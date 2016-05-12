#pragma once

#include "streams.h"

#include <memory>
#include <stddef.h>
#include <string>

struct statvfs;
struct timespec;

namespace securefs
{

class FileStream : public StreamBase
{
public:
    virtual int get_native_handle() noexcept = 0;
    virtual void fsync() = 0;
    virtual void utimens(const struct timespec ts[2]) = 0;
};

class RootDirectory
{
private:
    class Impl;
    std::unique_ptr<Impl> impl;

public:
    RootDirectory(const std::string& path, bool readonly);
    ~RootDirectory();
    std::shared_ptr<FileStream> open_file_stream(const std::string& path, int flags, unsigned mode);
    bool remove_file(const std::string& path) noexcept;
    bool remove_directory(const std::string& path) noexcept;
    void lock();
    void ensure_directory(const std::string& path, unsigned mode);
    void statfs(struct statvfs*);
};
}