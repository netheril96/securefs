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

#include <absl/base/thread_annotations.h>
#include <algorithm>
#include <exception>
#include <fruit/component.h>
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
        root_->initialize_empty(0755 | S_IFDIR, OSService::getuid(), OSService::getgid());
    }
}
FilePtrHolder FileTable::create_holder(FileBase* fb)
{
    fb->incref();
    return {fb, FileTableCloser(this)};
}
FilePtrHolder FileTable::create_holder(std::unique_ptr<FileBase>& fb)
{
    return create_holder(fb.get());
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
        return create_holder(it->second);
    }
    if (auto it
        = std::find_if(s.cache.begin(),
                       s.cache.end(),
                       [&](const std::unique_ptr<FileBase>& p) { return p->get_id() == id; });
        it != s.cache.end())
    {
        auto holder = create_holder(*it);
        auto unique_base = std::move(*it);
        s.cache.erase(it);
        s.live_map.emplace(id, std::move(unique_base));
        return holder;
    }
    auto [data, meta] = io_.open(id);
    auto unique_base = construct(type, std::move(data), std::move(meta), id);
    auto holder = create_holder(unique_base);
    s.live_map.emplace(id, std::move(unique_base));
    return holder;
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
    fp->setref(0);
    auto holder = create_holder(fp);
    s.live_map.emplace(id, std::move(fp));
    return holder;
}
std::unique_ptr<FileBase> FileTable::construct(int type,
                                               std::shared_ptr<FileStream> data_stream,
                                               std::shared_ptr<FileStream> meta_stream,
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
void FileTable::close(const id_type& id)
{
    pool_.detach_task(
        [this, id]()
        {
            try
            {
                close_internal(id);
            }
            catch (const std::exception& e)
            {
                ERROR_LOG("Failed background maintanence work: %s", e.what());
            }
        });
}
void FileTable::close_internal(const id_type& id)
{
    auto& s = find_shard(id);

    LockGuard<Mutex> lg(s.mu);
    auto it = s.live_map.find(id);
    if (it == s.live_map.end())
    {
        return;
    }
    if (it->second->getref() > 0)
    {
        return;    // Already reopened by another thread.
    }

    // The file descriptor is not referenced anywhere else, so we don't need to lock it.
    // If we do lock it, then later when it is destroyed, we are still holding the mutex,
    // which may cause undefined behavior.
    auto query_link_status = [](FileBase* fb) ABSL_NO_THREAD_SAFETY_ANALYSIS
    {
        bool result = fb->is_unlinked();
        if (!result)
        {
            fb->flush();
        }
        return result;
    };

    bool should_unlink = query_link_status(it->second.get());
    auto holder = std::move(it->second);
    s.live_map.erase(it);
    if (!should_unlink)
    {
        s.cache.emplace_back(std::move(holder));
    }
    else
    {
        holder.reset();
        io_.unlink(id);
    }
    if (s.cache.size() > kMaxCached)
    {
        static_assert(kEjectNumber < kMaxCached);
        auto begin = s.cache.begin();
        auto end = s.cache.begin() + kEjectNumber;
        for (auto it = begin; it != end; ++it)
        {
            if (it->get()->getref() > 0)
            {
                ERROR_LOG("A file descriptor in the closed pool has outstanding references");
                return;
            }
        }
        s.cache.erase(begin, end);
    }
};

FileTable::~FileTable()
{
    INFO_LOG("Flushing all opened and cached file descriptors, please wait...");
    root_->flush();
    for (auto&& s : shards)
    {
        pool_.detach_task(
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
    pool_.wait();
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

fruit::Component<fruit::Required<OSService, fruit::Annotated<tReadOnly, bool>>, FileTableIO>
get_table_io_component(bool legacy)
{
    if (legacy)
    {
        return fruit::createComponent().bind<FileTableIO, FileTableIOVersion1>();
    }
    return fruit::createComponent().bind<FileTableIO, FileTableIOVersion2>();
}
}    // namespace securefs::full_format
