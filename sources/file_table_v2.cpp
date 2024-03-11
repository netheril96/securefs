#include "file_table_v2.h"
#include "crypto.h"
#include "exceptions.h"
#include "files.h"
#include "lock_guard.h"
#include "logger.h"
#include "mystring.h"
#include "myutils.h"
#include "platform.h"
#include "tags.h"

#include <algorithm>
#include <asio/post.hpp>
#include <exception>
#include <fruit/macro.h>
#include <memory>

namespace securefs::full_format
{
void FileTable::init()
{
    FileStreamPtrPair pair;
    bool newly = false;
    try
    {
        pair = io_.open(kRootId);
    }
    catch (const ExceptionBase& e)
    {
        INFO_LOG("Root directory not initialized, creating... (%s)", e.what());
        pair = io_.create(kRootId);
        newly = true;
    }
    root_ = directory_factory_(pair.first, pair.second, kRootId);
    if (newly)
    {
        LockGuard<FileBase> lg(*root_);
        root_->initialize_empty(0755, OSService::getuid(), OSService::getgid());
    }
}
FilePtrHolder FileTable::open_as(const id_type& id, int type)
{
    if (id == kRootId)
    {
        if (type != Directory::class_type())
        {
            throw_runtime_error("Inconsistent type");
        }
        return {root_.get(), FileTableCloser(this)};
    }
    auto& s = find_shard(id);
    LockGuard<Mutex> lg(s.mu);
    if (auto it = s.live_map.find(id); it != s.live_map.end())
    {
        it->second->incref();
        return {it->second.get(), FileTableCloser(this)};
    }
    if (auto it
        = std::find_if(s.cache.begin(),
                       s.cache.end(),
                       [&](const std::unique_ptr<FileBase>& p) { return p->get_id() == id; });
        it != s.cache.end())
    {
        (**it).incref();
        auto holder = std::move(*it);
        FileBase* fp = holder.get();
        s.cache.erase(it);
        s.live_map.emplace(id, std::move(holder));
        return {fp, FileTableCloser(this)};
    }
    auto [data, meta] = io_.open(id);
    auto holder = construct(type, std::move(data), std::move(meta), id);
    holder->setref(1);
    FileBase* fp = holder.get();
    s.live_map.emplace(id, std::move(holder));
    return {fp, FileTableCloser(this)};
}
FileTable::Shard& FileTable::find_shard(const id_type& id)
{
    return shards[to_inode_number(id) % shards.size()];
}
FilePtrHolder FileTable::create_as(int type)
{
    id_type id;
    generate_random(id.data(), id.size());
    auto& s = find_shard(id);
    LockGuard<Mutex> lg(s.mu);
    auto [data, meta] = io_.create(id);
    auto fp = construct(type, std::move(data), std::move(meta), id);
    fp->setref(1);
    FilePtrHolder result(fp.get(), FileTableCloser(this));
    s.live_map.emplace(id, std::move(fp));
    return result;
}
std::unique_ptr<FileBase> FileTable::construct(int type,
                                               std::shared_ptr<StreamBase> data_stream,
                                               std::shared_ptr<StreamBase> meta_stream,
                                               const id_type& id)
{
    switch (type)
    {
    case RegularFile::class_type():
        return regular_file_factory_(std::move(data_stream), std::move(meta_stream), id);
    case Directory::class_type():
        return directory_factory_(std::move(data_stream), std::move(meta_stream), id);
    case Symlink::class_type():
        return symlink_factory_(std::move(data_stream), std::move(meta_stream), id);
    default:
        throw_runtime_error("Invalid file type");
    }
}
void FileTable::close(FileBase* fb)
{
    if (fb == root_.get())
    {
        return;
    }
    if (fb->decref() > 0)
    {
        return;
    }
    auto id = fb->get_id();    // Copy the ID because the pointer may be invalidated later.
    auto& s = find_shard(id);
    bool should_unlink = false;
    bool should_gc = false;
    {
        LockGuard<Mutex> lg(s.mu);
        if (fb->getref() > 0)
        {
            // Because we didn't lock the sharded mutex before, the refcount may have changed, and
            // therefore we need to double check.
            return;
        }
        if (auto it = s.live_map.find(id); it != s.live_map.end())
        {
            should_unlink = fb->is_unlinked();
            auto holder = std::move(it->second);
            s.live_map.erase(it);
            if (!should_unlink)
            {
                s.cache.emplace_back(std::move(holder));
            }
            should_gc = s.cache.size() > kMaxCached;
        }
        else
        {
            ERROR_LOG("Closing a file descriptor with id %s not within the table", hexify(id));
            return;
        }
    }
    if (should_unlink)
    {
        asio::post(pool_, [this, id]() { io_.unlink(id); });
    }
    if (should_gc)
    {
        asio::post(
            pool_,
            [&s]()
            {
                try
                {
                    LockGuard<Mutex> lg(s.mu);
                    if (s.cache.size() < kEjectNumber)
                    {
                        return;
                    }
                    auto begin = s.cache.begin();
                    auto end = s.cache.begin() + kEjectNumber;
                    for (auto it = begin; it != end; ++it)
                    {
                        LockGuard<FileBase> inner_lg(**it);
                        it->get()->flush();
                        if (it->get()->getref() > 0)
                        {
                            ERROR_LOG(
                                "A file descriptor in the closed pool has outstanding references");
                            return;
                        }
                    }
                    s.cache.erase(begin, end);
                }
                catch (const std::exception& e)
                {
                    ERROR_LOG(
                        "Exception during background maintenance of closed file descriptors: %s",
                        e.what());
                }
            });
    }
}
FileTable::~FileTable()
{
    INFO_LOG("Flushing all opened and cached file descriptors, please wait...");
    root_->flush();
    for (auto&& s : shards)
    {
        asio::post(pool_,
                   [&s]()
                   {
                       LockGuard<Mutex> lg(s.mu);
                       for (auto&& pair : s.live_map)
                       {
                           LockGuard<FileBase> inner_lg(*pair.second);
                           pair.second->flush();
                       }
                       for (auto&& p : s.cache)
                       {
                           LockGuard<FileBase> inner_lg(*p);
                           p->flush();
                       }
                   });
    }
    pool_.join();
}

namespace
{
    class FileTableIOVersion1 : public FileTableIO
    {
    private:
        OSService& m_root;
        bool m_readonly;

        static const size_t FIRST_LEVEL = 1, SECOND_LEVEL = 5;

        static void calculate_paths(const id_type& id,
                                    std::string& first_level_dir,
                                    std::string& second_level_dir,
                                    std::string& full_filename,
                                    std::string& meta_filename)
        {
            first_level_dir = securefs::hexify(id.data(), FIRST_LEVEL);
            second_level_dir = absl::StrCat(
                first_level_dir, "/", securefs::hexify(id.data() + FIRST_LEVEL, SECOND_LEVEL));
            full_filename = absl::StrCat(second_level_dir,
                                         "/",
                                         securefs::hexify(id.data() + FIRST_LEVEL + SECOND_LEVEL,
                                                          id.size() - FIRST_LEVEL - SECOND_LEVEL));
            meta_filename = full_filename + ".meta";
        }

    public:
        INJECT(FileTableIOVersion1(OSService& root, ANNOTATED(tReadOnly, bool) readonly))
            : m_root(root), m_readonly(readonly)
        {
        }

        FileStreamPtrPair open(const id_type& id) override
        {
            std::string first_level_dir, second_level_dir, filename, metaname;
            calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);

            int open_flags = m_readonly ? O_RDONLY : O_RDWR;
            return std::make_pair(m_root.open_file_stream(filename, open_flags, 0),
                                  m_root.open_file_stream(metaname, open_flags, 0));
        }

        FileStreamPtrPair create(const id_type& id) override
        {
            std::string first_level_dir, second_level_dir, filename, metaname;
            calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
            m_root.ensure_directory(first_level_dir, 0755);
            m_root.ensure_directory(second_level_dir, 0755);
            int open_flags = O_RDWR | O_CREAT | O_EXCL;
            return std::make_pair(m_root.open_file_stream(filename, open_flags, 0644),
                                  m_root.open_file_stream(metaname, open_flags, 0644));
        }

        void unlink(const id_type& id) noexcept override
        {
            std::string first_level_dir, second_level_dir, filename, metaname;
            calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
            m_root.remove_file_nothrow(filename);
            m_root.remove_file_nothrow(metaname);
            m_root.remove_directory_nothrow(second_level_dir);
            m_root.remove_directory_nothrow(second_level_dir);
        }
    };

    class FileTableIOVersion2 : public FileTableIO
    {
    private:
        OSService& m_root;
        bool m_readonly;

        static void calculate_paths(const id_type& id,
                                    std::string& dir,
                                    std::string& full_filename,
                                    std::string& meta_filename)
        {
            dir = securefs::hexify(id.data(), 1);
            full_filename = absl::StrCat(dir, "/", securefs::hexify(id.data() + 1, id.size() - 1));
            meta_filename = full_filename + ".meta";
        }

    public:
        INJECT(FileTableIOVersion2(OSService& root, ANNOTATED(tReadOnly, bool) readonly))
            : m_root(root), m_readonly(readonly)
        {
        }

        FileStreamPtrPair open(const id_type& id) override
        {
            std::string dir, filename, metaname;
            calculate_paths(id, dir, filename, metaname);

            int open_flags = m_readonly ? O_RDONLY : O_RDWR;
            return std::make_pair(m_root.open_file_stream(filename, open_flags, 0),
                                  m_root.open_file_stream(metaname, open_flags, 0));
        }

        FileStreamPtrPair create(const id_type& id) override
        {
            std::string dir, filename, metaname;
            calculate_paths(id, dir, filename, metaname);
            m_root.ensure_directory(dir, 0755);
            int open_flags = O_RDWR | O_CREAT | O_EXCL;
            return std::make_pair(m_root.open_file_stream(filename, open_flags, 0644),
                                  m_root.open_file_stream(metaname, open_flags, 0644));
        }

        void unlink(const id_type& id) noexcept override
        {
            std::string dir, filename, metaname;
            calculate_paths(id, dir, filename, metaname);
            m_root.remove_file_nothrow(filename);
            m_root.remove_file_nothrow(metaname);
            m_root.remove_directory_nothrow(dir);
        }
    };

}    // namespace
}    // namespace securefs::full_format
