#include "crypto.h"
#include "myutils.h"
#include "platform.h"

namespace securefs
{
const OSService& OSService::get_default()
{
    static const OSService service;
    return service;
}

std::string OSService::temp_name(const std::string& prefix, const std::string& suffix)
{
    byte random[16];
    generate_random(random, array_length(random));
    std::string result;
    result.reserve(prefix.size() + 32 + suffix.size());
    result.append(prefix.data(), prefix.size());
    result.append(hexify(random, array_length(random)));
    result.append(suffix.data(), suffix.size());
    return result;
}

void OSService::ensure_directory(const std::string& path, unsigned mode) const
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

bool OSService::remove_file_nothrow(const std::string& path) const noexcept
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

bool OSService::remove_directory_nothrow(const std::string& path) const noexcept
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

void OSService::recursive_traverse(const std::string& dir,
                                   const recursive_traverse_callback& callback) const
{
    auto traverser = create_traverser(dir);
    std::string name;
    struct fuse_stat st;

    while (traverser->next(&name, &st))
    {
        if (name == "." || name == "..")
            continue;
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

DirectoryTraverser::~DirectoryTraverser() = default;

ssize_t FileStream::getxattr(const char*, void*, size_t) { throw VFSException(ENOTSUP); }

void FileStream::setxattr(const char*, void*, size_t, int) { throw VFSException(ENOTSUP); }

ssize_t FileStream::listxattr(char*, size_t) { throw VFSException(ENOTSUP); }

void FileStream::removexattr(const char*) { throw VFSException(ENOTSUP); }

void POSIXColourSetter::use(Colour::Code _colourCode) noexcept
{
    switch (_colourCode)
    {
    case Colour::Default:
        return setColour("[0;39m");
    case Colour::White:
        return setColour("[0m");
    case Colour::Red:
        return setColour("[0;31m");
    case Colour::Green:
        return setColour("[0;32m");
    case Colour::Blue:
        return setColour("[0:34m");
    case Colour::Cyan:
        return setColour("[0;36m");
    case Colour::Yellow:
        return setColour("[0;33m");
    case Colour::Grey:
        return setColour("[1;30m");

    case Colour::LightGrey:
        return setColour("[0;37m");
    case Colour::BrightRed:
        return setColour("[1;31m");
    case Colour::BrightGreen:
        return setColour("[1;32m");
    case Colour::BrightWhite:
        return setColour("[1;37m");

    default:
        break;
    }
}

void POSIXColourSetter::setColour(const char* _escapeCode) noexcept
{
    putc('\033', m_fp);
    fputs(_escapeCode, m_fp);
}
}    // namespace securefs
