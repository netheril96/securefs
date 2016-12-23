#pragma once

#include "myutils.h"
#include "platform.h"
#include "streams.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

namespace securefs
{
class FileBase
{
private:
    static const size_t NUM_FLAGS = 7, HEADER_SIZE = 8 * 4, EXTENDED_HEADER_SIZE = 64,
                        ATIME_OFFSET = NUM_FLAGS * sizeof(uint32_t),
                        MTIME_OFFSET = ATIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t),
                        CTIME_OFFSET = MTIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t);

    static_assert(CTIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t) == EXTENDED_HEADER_SIZE,
                  "Constants are wrong!");

private:
    ptrdiff_t m_refcount;
    std::shared_ptr<HeaderBase> m_header;
    key_type m_key;
    id_type m_id;
    uint32_t m_flags[NUM_FLAGS];
    timespec m_atime, m_mtime, m_ctime;
    std::shared_ptr<FileStream> m_data_stream, m_meta_stream;
    bool m_dirty, m_check, m_store_time;

private:
    void read_header();

    [[noreturn]] void throw_invalid_cast(int to_type);

protected:
    std::shared_ptr<StreamBase> m_stream;

    uint32_t get_root_page() const noexcept { return m_flags[4]; }

    void set_root_page(uint32_t value) noexcept
    {
        m_flags[4] = value;
        m_dirty = true;
    }

    uint32_t get_start_free_page() const noexcept { return m_flags[5]; }

    void set_start_free_page(uint32_t value) noexcept
    {
        m_flags[5] = value;
        m_dirty = true;
    }

    uint32_t get_num_free_page() const noexcept { return m_flags[6]; }

    void set_num_free_page(uint32_t value) noexcept
    {
        m_flags[6] = value;
        m_dirty = true;
    }

    /**
     * Subclasss should override this if additional flush operations are needed
     */
    virtual void subflush() {}

public:
    static const byte REGULAR_FILE = S_IFREG >> 12, SYMLINK = S_IFLNK >> 12,
                      DIRECTORY = S_IFDIR >> 12, BASE = 255;

    static_assert(REGULAR_FILE != SYMLINK && SYMLINK != DIRECTORY,
                  "The value assigned are indistinguishable");

    static int error_number_for_not(int type) noexcept
    {
        switch (type)
        {
        case REGULAR_FILE:
            return EPERM;
        case SYMLINK:
            return EINVAL;
        case DIRECTORY:
            return ENOTDIR;
        }
        return EINVAL;
    }

    static mode_t mode_for_type(int type) noexcept { return type << 12; }

    static int type_for_mode(mode_t mode) noexcept { return mode >> 12; }

    static const char* type_name(int type) noexcept
    {
        switch (type)
        {
        case REGULAR_FILE:
            return "regular_file";
        case SYMLINK:
            return "symbolic_link";
        case DIRECTORY:
            return "directory";
        }
        return "unknown";
    }

public:
    explicit FileBase(std::shared_ptr<FileStream> data_stream,
                      std::shared_ptr<FileStream> meta_stream,
                      const key_type& key_,
                      const id_type& id_,
                      bool check,
                      unsigned block_size,
                      unsigned iv_size,
                      bool store_time = false);

    virtual ~FileBase();
    DISABLE_COPY_MOVE(FileBase)

    void initialize_empty(uint32_t mode, uint32_t uid, uint32_t gid);

    // --Begin of getters and setters for stats---
    uint32_t get_mode() const noexcept { return m_flags[0]; }

    void set_mode(uint32_t value) noexcept
    {
        if (get_mode() == value)
            return;
        m_flags[0] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_uid() const noexcept { return m_flags[1]; }

    void set_uid(uint32_t value) noexcept
    {
        if (get_uid() == value)
            return;
        m_flags[1] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_gid() const noexcept { return m_flags[2]; }

    void set_gid(uint32_t value) noexcept
    {
        if (get_gid() == value)
            return;
        m_flags[2] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_nlink() const noexcept { return m_flags[3]; }

    void set_nlink(uint32_t value) noexcept
    {
        if (get_nlink() == value)
            return;
        m_flags[3] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    void get_atime(timespec& out) const noexcept { out = m_atime; }

    void get_mtime(timespec& out) const noexcept { out = m_mtime; }

    void get_ctime(timespec& out) const noexcept { out = m_ctime; }

    void set_atime(const timespec& in) noexcept
    {
        m_atime = in;
        m_dirty = true;
    }

    void set_mtime(const timespec& in) noexcept
    {
        m_mtime = in;
        m_dirty = true;
    }

    void set_ctime(const timespec& in) noexcept
    {
        m_ctime = in;
        m_dirty = true;
    }

    void update_atime_helper()
    {
        if (m_store_time && (m_atime.tv_sec < m_mtime.tv_sec || m_atime.tv_sec < m_ctime.tv_sec))
        {
            OSService::get_current_time(m_atime);
            m_dirty = true;
        }
    }

    void update_mtime_helper()
    {
        if (m_store_time)
        {
            OSService::get_current_time(m_mtime);
            m_ctime = m_mtime;
            m_dirty = true;
        }
    }

    void update_ctime_helper()
    {
        if (m_store_time)
        {
            OSService::get_current_time(m_ctime);
            m_dirty = true;
        }
    }

    // --End of getters and setters for stats---

    const id_type& get_id() const { return m_id; }

    const key_type& get_key() const { return m_key; }

    ptrdiff_t incref() noexcept { return ++m_refcount; }

    ptrdiff_t decref() noexcept { return --m_refcount; }

    ptrdiff_t getref() const noexcept { return m_refcount; }

    void setref(ptrdiff_t value) noexcept { m_refcount = value; }

    virtual int type() const noexcept { return FileBase::BASE; }

    int get_real_type();

    bool is_unlinked() const noexcept { return get_nlink() <= 0; }

    void unlink()
    {
        auto nlink = get_nlink();
        --nlink;
        set_nlink(nlink);
    }

    void flush();

    void fsync()
    {
        m_data_stream->fsync();
        m_meta_stream->fsync();
    }

    void utimens(const struct timespec ts[2]);

    void stat(FUSE_STAT* st);

    ssize_t listxattr(char* buffer, size_t size);

    ssize_t getxattr(const char* name, char* value, size_t size);

    void setxattr(const char* name, const char* value, size_t size, int flags);

    void removexattr(const char* name);

    template <class T>
    T* cast_as()
    {
        if (type() != T::class_type())
            throw_invalid_cast(T::class_type());
        return static_cast<T*>(this);
    }
};

class RegularFile : public FileBase
{
public:
    static int class_type() { return FileBase::REGULAR_FILE; }

    template <class... Args>
    explicit RegularFile(Args&&... args) : FileBase(std::forward<Args>(args)...)
    {
    }

    int type() const noexcept override { return class_type(); }

    length_type read(void* output, offset_type off, length_type len)
    {
        update_atime_helper();
        return this->m_stream->read(output, off, len);
    }

    void write(const void* input, offset_type off, length_type len)
    {
        update_mtime_helper();
        return this->m_stream->write(input, off, len);
    }

    length_type size() const noexcept { return m_stream->size(); }

    void truncate(length_type new_size)
    {
        update_mtime_helper();
        return m_stream->resize(new_size);
    }
};

class Symlink : public FileBase
{
public:
    static int class_type() { return FileBase::SYMLINK; }

    template <class... Args>
    explicit Symlink(Args&&... args) : FileBase(std::forward<Args>(args)...)
    {
    }

    int type() const noexcept override { return class_type(); }

    std::string get()
    {
        std::string result(m_stream->size(), 0);
        auto rc = m_stream->read(&result[0], 0, result.size());
        result.resize(rc);
        update_atime_helper();
        return result;
    }

    void set(const std::string& path)
    {
        m_stream->write(path.data(), 0, path.size());
    }
};

class Directory : public FileBase
{
public:
    static const size_t MAX_FILENAME_LENGTH = 255;

public:
    static int class_type() { return FileBase::DIRECTORY; }

    template <class... Args>
    explicit Directory(Args&&... args) : FileBase(std::forward<Args>(args)...)
    {
    }

    int type() const noexcept override { return class_type(); }

public:
    typedef std::function<bool(const std::string&, const id_type&, int)> callback;

    bool get_entry(const std::string& name, id_type& id, int& type)
    {
        update_atime_helper();
        return get_entry_impl(name, id, type);
    }

    bool add_entry(const std::string& name, const id_type& id, int type)
    {
        update_mtime_helper();
        return add_entry_impl(name, id, type);
    }

    /**
     * Removes the entry while also report the info of said entry.
     * Returns false when the entry is not found.
     */
    bool remove_entry(const std::string& name, id_type& id, int& type)
    {
        update_mtime_helper();
        return remove_entry_impl(name, id, type);
    }

    /**
     * When callback returns false, the iteration will be terminated
     */
    void iterate_over_entries(const callback& cb)
    {
        update_atime_helper();
        return iterate_over_entries_impl(cb);
    }

    virtual bool empty() = 0;

protected:
    virtual bool get_entry_impl(const std::string& name, id_type& id, int& type) = 0;

    virtual bool add_entry_impl(const std::string& name, const id_type& id, int type) = 0;

    /**
     * Removes the entry while also report the info of said entry.
     * Returns false when the entry is not found.
     */
    virtual bool remove_entry_impl(const std::string& name, id_type& id, int& type) = 0;

    /**
     * When callback returns false, the iteration will be terminated
     */
    virtual void iterate_over_entries_impl(const callback& cb) = 0;
};

class SimpleDirectory : public Directory
{
private:
    std::unordered_map<std::string, std::pair<id_type, int>> m_table;
    bool m_dirty;

private:
    void initialize();

public:
    template <class... Args>
    explicit SimpleDirectory(Args&&... args) : Directory(std::forward<Args>(args)...)
    {
        initialize();
    }

    bool get_entry_impl(const std::string& name, id_type& id, int& type) override;

    bool add_entry_impl(const std::string& name, const id_type& id, int type) override;

    bool remove_entry_impl(const std::string& name, id_type& id, int& type) override;

    void subflush() override;

    void iterate_over_entries_impl(const callback& cb) override
    {
        for (const auto& pair : m_table)
        {
            if (!cb(pair.first, pair.second.first, pair.second.second))
                break;
        }
    }

    bool empty() noexcept override { return m_table.empty(); }

    ~SimpleDirectory();
};
}
