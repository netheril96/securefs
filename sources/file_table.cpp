#include "file_table.h"
#include "btree_dir.h"
#include "exceptions.h"
#include "logger.h"
#include "myutils.h"
#include "platform.h"

#include <algorithm>
#include <limits>
#include <queue>
#include <string.h>
#include <string>
#include <utility>
#include <vector>

namespace securefs
{

typedef std::pair<std::shared_ptr<FileStream>, std::shared_ptr<FileStream>> FileStreamPtrPair;
class FileTableIO
{
    DISABLE_COPY_MOVE(FileTableIO)

public:
    explicit FileTableIO() {}
    virtual ~FileTableIO() {}

    virtual FileStreamPtrPair open(const id_type& id) = 0;
    virtual FileStreamPtrPair create(const id_type& id) = 0;
    virtual void unlink(const id_type& id) noexcept = 0;
};

class FileTableIOVersion1 : public FileTableIO
{
private:
    std::shared_ptr<const OSService> m_root;
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
    explicit FileTableIOVersion1(std::shared_ptr<const OSService> root, bool readonly)
        : m_root(root), m_readonly(readonly)
    {
    }

    FileStreamPtrPair open(const id_type& id) override
    {
        std::string first_level_dir, second_level_dir, filename, metaname;
        calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);

        int open_flags = m_readonly ? O_RDONLY : O_RDWR;
        return std::make_pair(m_root->open_file_stream(filename, open_flags, 0),
                              m_root->open_file_stream(metaname, open_flags, 0));
    }

    FileStreamPtrPair create(const id_type& id) override
    {
        std::string first_level_dir, second_level_dir, filename, metaname;
        calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
        m_root->ensure_directory(first_level_dir.c_str(), 0755);
        m_root->ensure_directory(second_level_dir.c_str(), 0755);
        int open_flags = O_RDWR | O_CREAT | O_EXCL;
        return std::make_pair(m_root->open_file_stream(filename, open_flags, 0644),
                              m_root->open_file_stream(metaname, open_flags, 0644));
    }

    void unlink(const id_type& id) noexcept override
    {
        std::string first_level_dir, second_level_dir, filename, metaname;
        calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
        m_root->remove_file_nothrow(filename);
        m_root->remove_file_nothrow(metaname);
        m_root->remove_directory_nothrow(second_level_dir);
        m_root->remove_directory_nothrow(second_level_dir);
    }
};

class FileTableIOVersion2 : public FileTableIO
{
private:
    std::shared_ptr<const OSService> m_root;
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
    explicit FileTableIOVersion2(std::shared_ptr<const OSService> root, bool readonly)
        : m_root(root), m_readonly(readonly)
    {
    }

    FileStreamPtrPair open(const id_type& id) override
    {
        std::string dir, filename, metaname;
        calculate_paths(id, dir, filename, metaname);

        int open_flags = m_readonly ? O_RDONLY : O_RDWR;
        return std::make_pair(m_root->open_file_stream(filename, open_flags, 0),
                              m_root->open_file_stream(metaname, open_flags, 0));
    }

    FileStreamPtrPair create(const id_type& id) override
    {
        std::string dir, filename, metaname;
        calculate_paths(id, dir, filename, metaname);
        m_root->ensure_directory(dir, 0755);
        int open_flags = O_RDWR | O_CREAT | O_EXCL;
        return std::make_pair(m_root->open_file_stream(filename, open_flags, 0644),
                              m_root->open_file_stream(metaname, open_flags, 0644));
    }

    void unlink(const id_type& id) noexcept override
    {
        std::string dir, filename, metaname;
        calculate_paths(id, dir, filename, metaname);
        m_root->remove_file_nothrow(filename);
        m_root->remove_file_nothrow(metaname);
        m_root->remove_directory_nothrow(dir);
    }
};

FileTable::FileTable(int version,
                     std::shared_ptr<const OSService> root,
                     const key_type& master_key,
                     uint32_t flags,
                     unsigned block_size,
                     unsigned iv_size)
    : m_flags(flags), m_block_size(block_size), m_iv_size(iv_size), m_root(root)
{
    memcpy(m_master_key.data(), master_key.data(), master_key.size());
    switch (version)
    {
    case 1:
        m_fio.reset(new FileTableIOVersion1(root, is_readonly()));
        break;
    case 2:
    case 3:
        m_fio.reset(new FileTableIOVersion2(root, is_readonly()));
        break;
    default:
        throwInvalidArgumentException("Unknown version");
    }
}

FileTable::~FileTable()
{
    for (auto&& pair : m_files)
        finalize(pair.second);
}

FileBase* FileTable::open_as(const id_type& id, int type)
{
    auto it = m_files.find(id);
    if (it != m_files.end())
    {
        // Remove the marking that this id is closed
        auto closed_id_iter = std::find(m_closed_ids.begin(), m_closed_ids.end(), id);
        if (closed_id_iter != m_closed_ids.end())
            m_closed_ids.erase(closed_id_iter);

        if (it->second->type() != type)
            m_files.erase(it);
        else
        {
            it->second->incref();
            return it->second.get();
        }
    }

    std::shared_ptr<FileStream> data_fd, meta_fd;
    std::tie(data_fd, meta_fd) = m_fio->open(id);
    auto fb = btree_make_file_from_type(type,
                                        data_fd,
                                        meta_fd,
                                        m_master_key,
                                        id,
                                        is_auth_enabled(),
                                        m_block_size,
                                        m_iv_size,
                                        is_time_stored());
    fb->setref(1);
    auto result = fb.get();
    m_files.emplace(id, std::move(fb));
    return result;
}

FileBase* FileTable::create_as(const id_type& id, int type)
{
    if (is_readonly())
        throwVFSException(EROFS);
    if (m_files.find(id) != m_files.end())
        throwVFSException(EEXIST);

    std::shared_ptr<FileStream> data_fd, meta_fd;
    std::tie(data_fd, meta_fd) = m_fio->create(id);
    auto fb = btree_make_file_from_type(type,
                                        data_fd,
                                        meta_fd,
                                        m_master_key,
                                        id,
                                        is_auth_enabled(),
                                        m_block_size,
                                        m_iv_size,
                                        is_time_stored());
    fb->setref(1);
    auto result = fb.get();
    m_files.emplace(id, std::move(fb));
    return result;
}

void FileTable::close(FileBase* fb)
{
    if (!fb)
        throwVFSException(EFAULT);

    auto iter = m_files.find(fb->get_id());
    if (iter == m_files.end() || iter->second.get() != fb)
        throwInvalidArgumentException("ID does not match the table");

    if (fb->getref() <= 0)
        throwInvalidArgumentException("Closing an closed file");

    if (fb->decref() <= 0)
    {
        finalize(iter->second);
        if (iter->second)
        {
            // This means the file is not deleted
            // The handle shall remain in the cache
            m_closed_ids.push_back(iter->second->get_id());
            gc();
        }
        else
        {
            m_files.erase(iter);
        }
    }
}

void FileTable::eject()
{
    auto num_eject = std::min<size_t>(NUM_EJECT, m_closed_ids.size());
    for (size_t i = 0; i < num_eject; ++i)
    {
        m_files.erase(m_closed_ids[i]);
        if (global_logger->get_level() <= kLogTrace)
            global_logger->trace("Evicting file with ID=%s from cache",
                                 hexify(m_closed_ids[i]).c_str());
    }
    m_closed_ids.erase(m_closed_ids.begin(), m_closed_ids.begin() + num_eject);
}

void FileTable::finalize(std::unique_ptr<FileBase>& fb)
{
    if (!fb)
        return;

    if (fb->is_unlinked())
    {
        id_type id = fb->get_id();
        fb.reset();
        m_fio->unlink(id);
    }
    else
    {
        fb->flush();
    }
}

void FileTable::gc()
{
    if (m_closed_ids.size() >= MAX_NUM_CLOSED)
        eject();
}
}
