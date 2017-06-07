#include "myutils.h"
#include "platform.h"

#include <cryptopp/osrng.h>

namespace securefs
{
const OSService& OSService::get_default()
{
    static const OSService service;
    return service;
}

std::string OSService::temp_name(StringRef prefix, StringRef suffix)
{
    byte random[16];
    CryptoPP::OS_GenerateRandomBlock(false, random, array_length(random));
    std::string result;
    result.reserve(prefix.size() + 32 + suffix.size());
    result.append(prefix.data(), prefix.size());
    result.append(hexify(random, array_length(random)));
    result.append(suffix.data(), suffix.size());
    return result;
}

void OSService::ensure_directory(StringRef path, unsigned mode) const
{
    try
    {
        mkdir(path, mode);
    }
    catch (const ExceptionBase& e)
    {
        if (e.error_number() != EEXIST)
            throw;
    }
}

bool OSService::remove_file_nothrow(StringRef path) const noexcept
{
    try
    {
        remove_file(path);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool OSService::remove_directory_nothrow(StringRef path) const noexcept
{
    try
    {
        remove_directory(path);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

void OSService::recursive_traverse(StringRef dir, const recursive_traverse_callback& callback) const
{
    auto traverser = create_traverser(dir);
    std::string name;
    struct fuse_stat st;

    while (traverser->next(&name, &st))
    {
        if ((S_IFMT & st.st_mode) == S_IFDIR)
        {
            recursive_traverse(dir + "/" + name, callback);
        }
        else
        {
            callback(dir, name);
        }
    }
}

DirectoryTraverser::~DirectoryTraverser() {}

ssize_t FileStream::getxattr(const char*, void*, size_t) { throw VFSException(ENOTSUP); }

void FileStream::setxattr(const char*, void*, size_t, int) { throw VFSException(ENOTSUP); }

ssize_t FileStream::listxattr(char*, size_t) { throw VFSException(ENOTSUP); }

void FileStream::removexattr(const char*) { throw VFSException(ENOTSUP); }
}
