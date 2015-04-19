#include "operations.h"

#include <mutex>
#include <algorithm>
#include <utility>
#include <string>

namespace securefs
{
namespace internal
{
    class FileGuard
    {
    private:
        FileTable* m_ft;
        FileBase* m_fb;

    public:
        explicit FileGuard(FileTable* ft, FileBase* fb) : m_ft(ft), m_fb(fb) {}

        FileGuard(const FileGuard&) = delete;
        FileGuard& operator=(const FileGuard&) = delete;

        FileGuard(FileGuard&& other) noexcept : m_ft(other.m_ft), m_fb(other.m_fb)
        {
            other.m_ft = nullptr;
            other.m_fb = nullptr;
        }

        FileGuard& operator=(FileGuard&& other) noexcept
        {
            if (this == &other)
                return *this;
            swap(other);
            return *this;
        }

        ~FileGuard()
        {
            try
            {
                reset(nullptr);
            }
            catch (...)
            {
            }
        }

        FileBase* get() noexcept { return m_fb; }
        template <class T>
        T* get_as() noexcept
        {
            return static_cast<T*>(m_fb);
        }
        FileBase& operator*() noexcept { return *m_fb; }
        FileBase* operator->() noexcept { return m_fb; }
        FileBase* release() noexcept
        {
            auto rt = m_fb;
            m_fb = nullptr;
            return rt;
        }
        void reset(FileBase* fb)
        {
            if (m_ft && m_fb)
            {
                std::lock_guard<FileTable> lg(*m_ft);
                m_ft->close(m_fb);
            }
            m_fb = fb;
        }
        void swap(FileGuard& other) noexcept
        {
            std::swap(m_ft, other.m_ft);
            std::swap(m_fb, other.m_fb);
        }
    };

    FileBase* table_open_as(FileTable& t, const id_type& id, int type)
    {
        std::lock_guard<FileTable> lg(t);
        return t.open_as(id, type);
    }

    FileBase* table_create_as(FileTable& t, const id_type& id, int type)
    {
        std::lock_guard<FileTable> lg(t);
        return t.create_as(id, type);
    }

    bool dir_get_entry(Directory* dir, const std::string& name, id_type& id, int& type)
    {
        assert(dir);
        std::lock_guard<FileBase> lg(*dir);
        return dir->get_entry(name, id, type);
    }

    bool dir_add_entry(Directory* dir, const std::string& name, const id_type& id, int type)
    {
        assert(dir);
        std::lock_guard<FileBase> lg(*dir);
        return dir->add_entry(name, id, type);
    }

    FileGuard
    open_base_dir(struct fuse_context* ctx, const std::string& path, std::string& last_component)
    {
        assert(ctx);
        auto components = split(path, '/');
        auto fs = static_cast<operations::FileSystem*>(ctx->private_data);
        FileGuard result(&fs->table, table_open_as(fs->table, fs->root_id, FileBase::DIRECTORY));
        if (components.empty())
        {
            last_component = std::string();
            return result;
        }
        id_type id;
        int type;

        for (size_t i = 0; i + 1 < components.size(); ++i)
        {
            bool exists = dir_get_entry(result.get_as<Directory>(), components[i], id, type);
            if (!exists)
                throw OSException(ENOENT);
            if (type != FileBase::DIRECTORY)
                throw OSException(ENOTDIR);
            result.reset(table_open_as(fs->table, id, type));
        }
        last_component = components.back();
        return result;
    }

    FileGuard open_all(struct fuse_context* ctx, const std::string& path)
    {
        auto fs = static_cast<operations::FileSystem*>(ctx->private_data);
        std::string last_component;
        auto fg = open_base_dir(ctx, path, last_component);
        if (last_component.empty())
            return fg;
        id_type id;
        int type;
        bool exists = dir_get_entry(fg.get_as<Directory>(), last_component, id, type);
        if (!exists)
            throw OSException(ENOENT);
        fg.reset(table_open_as(fs->table, id, type));
        return fg;
    }

    FileGuard create(struct fuse_context* ctx, const std::string& path, int type)
    {
        auto fs = static_cast<operations::FileSystem*>(ctx->private_data);
        std::string last_component;
        auto dir = open_base_dir(ctx, path, last_component);
        id_type id;
        generate_random(id.data(), id.size());
        FileGuard result(&fs->table, table_create_as(fs->table, id, type));
        bool success = false;
        try
        {
            success = dir_add_entry(dir.get_as<Directory>(), last_component, id, type);
        }
        catch (...)
        {
            result->unlink();
            throw;
        }
        if (!success)
        {
            result->unlink();
            throw OSException(EEXIST);
        }
        return result;
    }
}

namespace operations
{
    int getattr(const char* path, struct stat* st)
    {
        try
        {
            auto fg = internal::open_all(fuse_get_context(), path);
            fg->stat(st);
            return 0;
        }
        catch (const ExceptionBase& e)
        {
            fprintf(stderr, "%s\n", e.message().c_str());
            return -e.error_number();
        }
    }
}
}
