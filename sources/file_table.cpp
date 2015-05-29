#include "file_table.h"
#include "utils.h"
#include "exceptions.h"
#include "btree_dir.h"

#include <vector>
#include <limits>
#include <algorithm>
#include <utility>
#include <string>
#include <string.h>

#include <cryptopp/osrng.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

#include <fcntl.h>
#include <unistd.h>

namespace
{

const size_t FIRST_LEVEL = 1, SECOND_LEVEL = 5;

void calculate_paths(const securefs::id_type& id,
                     std::string& first_level_dir,
                     std::string& second_level_dir,
                     std::string& full_filename,
                     std::string& meta_filename)
{
    first_level_dir = securefs::hexify(id.data(), FIRST_LEVEL);
    second_level_dir = first_level_dir + '/'
        + securefs::hexify(id.data() + FIRST_LEVEL, SECOND_LEVEL);
    full_filename = second_level_dir + '/'
        + securefs::hexify(id.data() + FIRST_LEVEL + SECOND_LEVEL,
                           id.size() - FIRST_LEVEL - SECOND_LEVEL);
    meta_filename = full_filename + ".meta";
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

FileTable::~FileTable()
{
    for (auto&& pair : m_files)
    {
        try
        {
            finalize(pair.second.get());
        }
        catch (...)
        {
        }
    }
}

FileBase* FileTable::open_as(const id_type& id, int type)
{
    auto it = m_files.find(id);
    if (it != m_files.end())
    {
        auto fp = it->second.get();
        if (fp->type() != type)
            throw OSException(FileBase::error_number_for_not(type));
        return fp;
    }

    std::string first_level_dir, second_level_dir, filename, metaname;
    calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
    int open_flags = is_readonly() ? O_RDONLY : O_RDWR;
    int data_fd = ::openat(m_dir_fd, filename.c_str(), open_flags);
    if (data_fd < 0)
        throw OSException(errno);
    int meta_fd = ::openat(m_dir_fd, metaname.c_str(), open_flags);
    if (meta_fd < 0)
    {
        ::close(data_fd);
        throw OSException(errno);
    }
    auto fb
        = btree_make_file_from_type(type, data_fd, meta_fd, m_master_key, id, is_auth_enabled());
    m_files.emplace(id, fb);
    return fb.get();
}

FileBase* FileTable::create_as(const id_type& id, int type)
{
    if (is_readonly())
        throw OSException(EROFS);
    if (m_files.find(id) != m_files.end())
        throw OSException(EEXIST);

    std::string first_level_dir, second_level_dir, filename, metaname;
    calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
    int data_fd = -1, meta_fd = -1;
    try
    {
        ensure_directory(m_dir_fd, first_level_dir.c_str(), 0755);
        ensure_directory(m_dir_fd, second_level_dir.c_str(), 0755);
        data_fd = ::openat(m_dir_fd, filename.c_str(), O_RDWR | O_CREAT | O_EXCL, 0644);
        if (data_fd < 0)
            throw OSException(errno);
        meta_fd = ::openat(m_dir_fd, metaname.c_str(), O_RDWR | O_CREAT | O_EXCL, 0644);
        if (meta_fd < 0)
            throw OSException(errno);

        auto fb = btree_make_file_from_type(
            type, data_fd, meta_fd, m_master_key, id, is_auth_enabled());
        m_files.emplace(id, fb);
        return fb.get();
    }
    catch (...)
    {
        if (data_fd >= 0)
        {
            ::close(data_fd);
            ::unlinkat(m_dir_fd, filename.c_str(), 0);
        }
        if (meta_fd >= 0)
        {
            ::close(meta_fd);
            ::unlinkat(m_dir_fd, metaname.c_str(), 0);
        }
        ::unlinkat(m_dir_fd, second_level_dir.c_str(), AT_REMOVEDIR);
        ::unlinkat(m_dir_fd, first_level_dir.c_str(), AT_REMOVEDIR);
        throw;
    }
}

void FileTable::finalize(FileBase* fb)
{
    if (!fb)
        return;

    if (fb->is_unlinked())
    {
        std::string first_level_dir, second_level_dir, filename, metaname;
        calculate_paths(fb->get_id(), first_level_dir, second_level_dir, filename, metaname);
        ::unlinkat(m_dir_fd, filename.c_str(), 0);
        ::unlinkat(m_dir_fd, metaname.c_str(), 0);
        ::unlinkat(m_dir_fd, second_level_dir.c_str(), AT_REMOVEDIR);
        ::unlinkat(m_dir_fd, first_level_dir.c_str(), AT_REMOVEDIR);
    }
    else
    {
        fb->flush();
    }
}
}
