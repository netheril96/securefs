#include "file_table.h"
#include "btree_dir.h"
#include "exceptions.h"
#include "platform.h"
#include "utils.h"

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
    std::shared_ptr<RootDirectory> m_root;
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
    explicit FileTableIOVersion1(std::shared_ptr<RootDirectory> root, bool readonly)
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
        m_root->remove_file(filename);
        m_root->remove_file(metaname);
        m_root->remove_directory(second_level_dir);
        m_root->remove_directory(second_level_dir);
    }
};

class FileTableIOVersion2 : public FileTableIO
{
private:
    std::shared_ptr<RootDirectory> m_root;
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
    explicit FileTableIOVersion2(std::shared_ptr<RootDirectory> root, bool readonly)
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
        m_root->remove_file(filename);
        m_root->remove_file(metaname);
        m_root->remove_directory(dir);
    }
};

FileTable::FileTable(int version,
                     std::shared_ptr<RootDirectory> root,
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
        m_fio.reset(new FileTableIOVersion2(root, is_readonly()));
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

    std::shared_ptr<FileStream> data_fd, meta_fd;
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

    std::shared_ptr<FileStream> data_fd, meta_fd;
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
