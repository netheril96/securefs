#pragma once

#include <memory>
#include <stddef.h>
#include <string>

struct statvfs;

namespace securefs
{
class StreamBase;

class RootDirectory
{
private:
    class Impl;
    std::unique_ptr<Impl> impl;

public:
    RootDirectory(const std::string& path, bool readonly);
    ~RootDirectory();
    std::shared_ptr<StreamBase> open_file_stream(const std::string& path, int flags, unsigned mode);
    bool remove_file(const std::string& path) noexcept;
    bool remove_directory(const std::string& path) noexcept;
    void lock();
    void ensure_directory(const std::string& path, unsigned mode);
    void statfs(struct statvfs*);
};
}