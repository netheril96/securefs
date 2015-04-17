#include "file_table.h"

#include <cryptopp/osrng.h>

#include <fcntl.h>
#include <unistd.h>

namespace
{
void ensure_directory(int base_fd, const char* dir_name, mode_t mode)
{
    int rc = ::mkdirat(base_fd, dir_name, mode);
    if (rc < 0 && errno != EEXIST)
        throw securefs::OSException(errno);
}

void rmdir_if_empty(int base_fd, const char* dir_name)
{
    int rc = ::unlinkat(base_fd, dir_name, AT_REMOVEDIR);
    if (rc < 0 && errno != ENOTEMPTY)
        throw securefs::OSException(errno);
}

void remove(int base_fd, const char* dir_name)
{
    int rc = ::unlinkat(base_fd, dir_name, 0);
    if (rc < 0)
        throw securefs::OSException(errno);
}
}

namespace securefs
{
FileTable::id_hash::id_hash()
{
    CryptoPP::NonblockingRng rng;
    rng.GenerateBlock(reinterpret_cast<byte*>(&m_seed), sizeof(m_seed));
}

size_t FileTable::id_hash::operator()(const id_type& id) const noexcept
{
    return from_little_endian<size_t>(id.data() + (id.size() - sizeof(size_t))) ^ m_seed;
}

FileBase* FileTable::open_as(const id_type& id, int type)
{
    auto it = m_opened.find(id);
    if (it != m_opened.end())
    {
        it->second->incref();
        return it->second.get();
    }
    return nullptr;
}
}
