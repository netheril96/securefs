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

    FileGuard
    open_base_dir(struct fuse_context* ctx, const std::string& path, std::string& last_component)
    {
        assert(ctx);
        auto components = split(path, '/');
        auto fs = static_cast<operations::FileSystem*>(ctx->private_data);
        FileGuard result(&fs->table, nullptr);
        {
            std::lock_guard<FileTable> lg(fs->table);
            result.reset(fs->table.open_as(fs->root_id, FileBase::DIRECTORY));
        }
        if (components.empty())
            return result;

        id_type id;
        int type;
        bool exists;

        for (size_t i = 0; i + 1 < components.size(); ++i)
        {
            {
                std::lock_guard<FileBase> lg(*result);
                exists = result.get_as<Directory>()->get_entry(components[i], id, type);
            }
            if (!exists)
                throw OSException(ENOENT);
            if (type != FileBase::DIRECTORY)
                throw OSException(ENOTDIR);
            std::lock_guard<FileTable> lg(fs->table);
            result.reset(fs->table.open_as(id, type));
        }
        last_component = components.back();
        return result;
    }

    FileGuard open_all(struct fuse_context* ctx, const std::string& path)
    {
        auto fs = static_cast<operations::FileSystem*>(ctx->private_data);
        std::string last_component;
        auto fg = open_base_dir(ctx, path, last_component);
        id_type id;
        int type;
        bool exists;
        {
            std::lock_guard<FileBase> lg(*fg);
            exists = fg.get_as<Directory>()->get_entry(last_component, id, type);
        }
        if (!exists)
            throw OSException(ENOENT);
        std::lock_guard<FileTable> lg(fs->table);
        fg.reset(fs->table.open_as(id, type));
        return fg;
    }
}
}
