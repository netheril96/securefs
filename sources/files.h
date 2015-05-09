#pragma once
#include "utils.h"
#include "streams.h"

#include <mutex>
#include <string>
#include <memory>
#include <functional>

namespace securefs
{
class FileBase
{
private:
    std::mutex m_lock;
    ptrdiff_t m_refcount;
    std::shared_ptr<HeaderBase> m_header;
    key_type m_key;
    id_type m_id;
    uint32_t m_flags[7];
    int m_data_fd, m_meta_fd;
    bool m_dirty, m_check;

private:
    void read_header();

protected:
    std::shared_ptr<StreamBase> m_stream;
    bool m_removed;

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
                      DIRECTORY = S_IFDIR >> 12;

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

public:
    explicit FileBase(
        int data_fd, int meta_fd, const key_type& key_, const id_type& id_, bool check);
    virtual ~FileBase();
    DISABLE_COPY_MOVE(FileBase);

    // --Begin of getters and setters for stats---
    uint32_t get_mode() const noexcept { return m_flags[0]; }
    void set_mode(uint32_t value) noexcept
    {
        m_flags[0] = value;
        m_dirty = true;
    }
    uint32_t get_uid() const noexcept { return m_flags[1]; }
    void set_uid(uint32_t value) noexcept
    {
        m_flags[1] = value;
        m_dirty = true;
    }
    uint32_t get_gid() const noexcept { return m_flags[2]; }
    void set_gid(uint32_t value) noexcept
    {
        m_flags[2] = value;
        m_dirty = true;
    }
    uint32_t get_nlink() const noexcept { return m_flags[3]; }
    void set_nlink(uint32_t value) noexcept
    {
        m_flags[3] = value;
        m_dirty = true;
    }
    // --End of getters and setters for stats---

    const id_type& get_id() const { return m_id; }
    const key_type& get_key() const { return m_key; }

    void lock() { m_lock.lock(); }
    void unlock() { m_lock.unlock(); }

    ptrdiff_t incref() noexcept { return ++m_refcount; }
    ptrdiff_t decref() noexcept { return --m_refcount; }
    ptrdiff_t getref() const noexcept { return m_refcount; }
    void setref(ptrdiff_t value) noexcept { m_refcount = value; }

    virtual int type() const noexcept = 0;
    bool is_unlinked() const noexcept { return m_removed; }
    virtual void unlink() = 0;

    void flush();
    void stat(struct stat* st)
    {
        if (!st)
            throw OSException(EFAULT);
        int rc = ::fstat(file_descriptor(), st);
        if (rc < 0)
            throw OSException(errno);

        st->st_uid = get_uid();
        st->st_gid = get_gid();
        st->st_nlink = get_nlink();
        st->st_mode = get_mode();
        st->st_size = m_stream->size();
        auto blk_sz = m_stream->optimal_block_size();
        if (blk_sz > 1 && blk_sz < std::numeric_limits<decltype(st->st_blksize)>::max())
        {
            st->st_blksize = static_cast<decltype(st->st_blksize)>(blk_sz);
            st->st_blocks = (st->st_size + st->st_blksize - 1) / st->st_blksize;
        }
    }
    int file_descriptor() const { return m_data_fd; }
    ssize_t listxattr(char* buffer, size_t size);

    ssize_t getxattr(const char* name, char* value, size_t size);
    void setxattr(const char* name, const char* value, size_t size, int flags);
    void removexattr(const char* name);
};

class RegularFile : public FileBase
{
public:
    template <class... Args>
    explicit RegularFile(Args&&... args)
        : FileBase(std::forward<Args>(args)...)
    {
    }
    int type() const noexcept override { return FileBase::REGULAR_FILE; }
    length_type read(void* output, offset_type off, length_type len)
    {
        return this->m_stream->read(output, off, len);
    }
    void write(const void* input, offset_type off, length_type len)
    {
        return this->m_stream->write(input, off, len);
    }
    length_type size() const noexcept { return m_stream->size(); }
    void truncate(length_type new_size) { return m_stream->resize(new_size); }
    void unlink() override
    {
        auto nlink = get_nlink();
        --nlink;
        set_nlink(nlink);
        if (nlink == 0)
            m_removed = true;
    }
};

class Symlink : public FileBase
{
public:
    template <class... Args>
    explicit Symlink(Args&&... args)
        : FileBase(std::forward<Args>(args)...)
    {
    }
    int type() const noexcept override { return FileBase::SYMLINK; }
    std::string get()
    {
        std::string result(m_stream->size(), 0);
        auto rc = m_stream->read(&result[0], 0, result.size());
        result.resize(rc);
        return result;
    }
    void set(const std::string& path) { m_stream->write(path.data(), 0, path.size()); }
    void unlink() override { m_removed = true; }
};

class Directory : public FileBase
{
public:
    static const size_t MAX_FILENAME_LENGTH = 255;

public:
    template <class... Args>
    explicit Directory(Args&&... args)
        : FileBase(std::forward<Args>(args)...)
    {
    }

    int type() const noexcept override { return FileBase::DIRECTORY; }

    virtual bool get_entry(const std::string& name, id_type& id, int& type) = 0;
    virtual bool add_entry(const std::string& name, const id_type& id, int type) = 0;

    /**
     * Removes the entry while also report the info of said entry.
     * Returns false when the entry is not found.
     */
    virtual bool remove_entry(const std::string& name, id_type& id, int& type) = 0;

    typedef std::function<bool(const std::string&, const id_type&, int)> callback;
    /**
     * When callback returns false, the iteration will be terminated
     */
    virtual void iterate_over_entries(callback cb) = 0;

    virtual bool empty() const = 0;
    void unlink() override
    {
        if (empty())
            m_removed = true;
        else
            throw OSException(ENOTEMPTY);
    }
};

std::shared_ptr<Directory>
make_directory(int data_fd, int meta_fd, const key_type& key_, const id_type& id_, bool check);

template <class... Args>
inline std::shared_ptr<FileBase> make_file_from_type(int type, Args&&... args)
{
    switch (type)
    {
    case FileBase::REGULAR_FILE:
        return std::make_shared<RegularFile>(std::forward<Args>(args)...);
    case FileBase::SYMLINK:
        return std::make_shared<Symlink>(std::forward<Args>(args)...);
    case FileBase::DIRECTORY:
        return make_directory(std::forward<Args>(args)...);
    }
    throw InvalidArgumentException("Unrecognized file type");
}
}
