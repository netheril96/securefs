#include "file_table.h"
#include "btree_dir.h"
#include "exceptions.h"
#include "utils.h"

#include <algorithm>
#include <limits>
#include <queue>
#include <string.h>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace securefs
{

class FileTableIO
{
    DISABLE_COPY_MOVE(FileTableIO);

public:
    explicit FileTableIO() {}
    virtual ~FileTableIO() {}

    virtual std::pair<int, int> open(const id_type& id) = 0;
    virtual std::pair<int, int> create(const id_type& id) = 0;
    virtual void unlink(const id_type& id) noexcept = 0;
};

class FileTableIOVersion1 : public FileTableIO
{
private:
    int m_dir_fd;
    bool m_readonly;

    static const size_t FIRST_LEVEL = 1, SECOND_LEVEL = 5;

    static void calculate_paths(const securefs::id_type& id,
                                std::string& first_level_dir,
                                std::string& second_level_dir,
                                std::string& full_filename,
                                std::string& meta_filename)
    {
        first_level_dir = securefs::hexify(id.data(), FIRST_LEVEL);
        second_level_dir
            = first_level_dir + '/' + securefs::hexify(id.data() + FIRST_LEVEL, SECOND_LEVEL);
        full_filename
            = second_level_dir + '/' + securefs::hexify(id.data() + FIRST_LEVEL + SECOND_LEVEL,
                                                        id.size() - FIRST_LEVEL - SECOND_LEVEL);
        meta_filename = full_filename + ".meta";
    }

public:
    explicit FileTableIOVersion1(int dir_fd, bool readonly) : m_dir_fd(dir_fd), m_readonly(readonly)
    {
    }

    std::pair<int, int> open(const id_type& id) override
    {
        std::string first_level_dir, second_level_dir, filename, metaname;
        calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);

        int open_flags = m_readonly ? O_RDONLY : O_RDWR;
        int data_fd = ::openat(m_dir_fd, filename.c_str(), open_flags);
        if (data_fd < 0)
            throw UnderlyingOSException(errno, fmt::format("Error opening {}", filename));
        int meta_fd = ::openat(m_dir_fd, metaname.c_str(), open_flags);
        if (meta_fd < 0)
        {
            ::close(data_fd);
            throw UnderlyingOSException(errno, fmt::format("Error opening {}", metaname));
        }
        return std::make_pair(data_fd, meta_fd);
    }

    std::pair<int, int> create(const id_type& id) override
    {
        std::string first_level_dir, second_level_dir, filename, metaname;
        calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
        int data_fd = -1, meta_fd = -1;
        try
        {
            ensure_directory(m_dir_fd, first_level_dir.c_str(), 0755);
            ensure_directory(m_dir_fd, second_level_dir.c_str(), 0755);
            data_fd = ::openat(m_dir_fd, filename.c_str(), O_RDWR | O_CREAT | O_EXCL, 0644);
            if (data_fd < 0)
                throw UnderlyingOSException(errno, fmt::format("Error creating {}", filename));
            meta_fd = ::openat(m_dir_fd, metaname.c_str(), O_RDWR | O_CREAT | O_EXCL, 0644);
            if (meta_fd < 0)
                throw UnderlyingOSException(errno, fmt::format("Error creating {}", metaname));

            return std::make_pair(data_fd, meta_fd);
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

    void unlink(const id_type& id) noexcept override
    {
        std::string first_level_dir, second_level_dir, filename, metaname;
        calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
        ::unlinkat(m_dir_fd, filename.c_str(), 0);
        ::unlinkat(m_dir_fd, metaname.c_str(), 0);
        ::unlinkat(m_dir_fd, second_level_dir.c_str(), AT_REMOVEDIR);
        ::unlinkat(m_dir_fd, first_level_dir.c_str(), AT_REMOVEDIR);
    }
};

class FileTableIOVersion2 : public FileTableIO
{
private:
    int m_dir_fd;
    bool m_readonly;

    static void calculate_paths(const securefs::id_type& id,
                                std::string& dir,
                                std::string& full_filename,
                                std::string& meta_filename)
    {
        dir = securefs::hexify(id.data(), 1);
        full_filename = dir + '/' + securefs::hexify(id.data() + 1, id.size() - 1);
        meta_filename = full_filename + ".meta";
    }

public:
    explicit FileTableIOVersion2(int dir_fd, bool readonly) : m_dir_fd(dir_fd), m_readonly(readonly)
    {
    }

    std::pair<int, int> open(const id_type& id) override
    {
        std::string dir, filename, metaname;
        calculate_paths(id, dir, filename, metaname);

        int open_flags = m_readonly ? O_RDONLY : O_RDWR;
        int data_fd = ::openat(m_dir_fd, filename.c_str(), open_flags);
        if (data_fd < 0)
            throw UnderlyingOSException(errno, fmt::format("Error opening {}", filename));
        int meta_fd = ::openat(m_dir_fd, metaname.c_str(), open_flags);
        if (meta_fd < 0)
        {
            ::close(data_fd);
            throw UnderlyingOSException(errno, fmt::format("Error opening {}", metaname));
        }
        return std::make_pair(data_fd, meta_fd);
    }

    std::pair<int, int> create(const id_type& id) override
    {
        std::string dir, filename, metaname;
        calculate_paths(id, dir, filename, metaname);
        int data_fd = -1, meta_fd = -1;

        try
        {
            ensure_directory(m_dir_fd, dir.c_str(), 0755);
            data_fd = ::openat(m_dir_fd, filename.c_str(), O_RDWR | O_CREAT | O_EXCL, 0644);
            if (data_fd < 0)
                throw UnderlyingOSException(errno, fmt::format("Error creating {}", filename));
            meta_fd = ::openat(m_dir_fd, metaname.c_str(), O_RDWR | O_CREAT | O_EXCL, 0644);
            if (meta_fd < 0)
                throw UnderlyingOSException(errno, fmt::format("Error creating {}", metaname));

            return std::make_pair(data_fd, meta_fd);
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
            ::unlinkat(m_dir_fd, dir.c_str(), AT_REMOVEDIR);
            throw;
        }
    }

    void unlink(const id_type& id) noexcept override
    {
        std::string dir, filename, metaname;
        calculate_paths(id, dir, filename, metaname);
        ::unlinkat(m_dir_fd, filename.c_str(), 0);
        ::unlinkat(m_dir_fd, metaname.c_str(), 0);
        ::unlinkat(m_dir_fd, dir.c_str(), AT_REMOVEDIR);
    }
};

FileTable::FileTable(int version,
                     int dir_fd,
                     const key_type& master_key,
                     uint32_t flags,
                     unsigned block_size,
                     unsigned iv_size)
    : m_flags(flags), m_block_size(block_size), m_iv_size(iv_size)
{
    memcpy(m_master_key.data(), master_key.data(), master_key.size());
    switch (version)
    {
    case 1:
        m_fio.reset(new FileTableIOVersion1(dir_fd, is_readonly()));
        break;
    case 2:
        m_fio.reset(new FileTableIOVersion2(dir_fd, is_readonly()));
        break;
    default:
        throw InvalidArgumentException("Unknown version");
    }
}

FileTable::~FileTable()
{
    for (auto&& pair : m_opened)
        finalize(pair.second.get());
    for (auto&& pair : m_closed)
        finalize(pair.second.get());
}

FileBase* FileTable::open_as(const id_type& id, int type)
{
    auto it = m_opened.find(id);
    if (it != m_opened.end())
    {
        if (it->second->type() != type)
            throw OSException(FileBase::error_number_for_not(type));
        it->second->incref();
        return it->second.get();
    }

    it = m_closed.find(id);
    if (it != m_closed.end())
    {
        if (it->second->type() != type)
        {
            m_closed.erase(it);
        }
        else
        {
            auto fb = it->second;
            m_opened.emplace(*it);
            m_closed.erase(it);
            fb->setref(1);
            return fb.get();
        }
    }

    int data_fd, meta_fd;
    std::tie(data_fd, meta_fd) = m_fio->open(id);
    auto fb = btree_make_file_from_type(
        type, data_fd, meta_fd, m_master_key, id, is_auth_enabled(), m_block_size, m_iv_size);
    m_opened.emplace(id, fb);
    fb->setref(1);
    return fb.get();
}

FileBase* FileTable::create_as(const id_type& id, int type)
{
    if (is_readonly())
        throw OSException(EROFS);
    if (m_opened.find(id) != m_opened.end() || m_closed.find(id) != m_closed.end())
        throw OSException(EEXIST);

    int data_fd, meta_fd;
    std::tie(data_fd, meta_fd) = m_fio->create(id);
    auto fb = btree_make_file_from_type(
        type, data_fd, meta_fd, m_master_key, id, is_auth_enabled(), m_block_size, m_iv_size);
    m_opened.emplace(id, fb);
    fb->setref(1);
    return fb.get();
}

void FileTable::close(FileBase* fb)
{
    if (!fb)
        NULL_EXCEPT();

    auto fb_shared = m_opened.at(fb->get_id());
    if (fb_shared.get() != fb)
        throw InvalidArgumentException("ID does not match the table");

    if (fb->decref() <= 0)
    {
        m_opened.erase(fb->get_id());
        finalize(fb);

        if (fb->is_unlinked())
            return;
        m_closed.emplace(fb->get_id(), fb_shared);
        m_closed_ids.push(fb->get_id());
        gc();
    }
}

void FileTable::eject()
{
    for (int i = 0; i < NUM_EJECT; ++i)
    {
        if (m_closed_ids.empty())
            break;
        m_closed.erase(m_closed_ids.front());
        m_closed_ids.pop();
    }
}

void FileTable::finalize(FileBase* fb)
{
    if (!fb)
        return;

    if (fb->is_unlinked())
    {
        m_fio->unlink(fb->get_id());
    }
    else
    {
        fb->flush();
    }
}

void FileTable::gc()
{
    if (m_closed.size() >= NUM_EJECT)
        eject();
}
}
