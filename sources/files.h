#pragma once

#include "myutils.h"
#include "platform.h"
#include "streams.h"
#include "thread_safety_annotations.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rng.h>

namespace securefs
{
class RegularFile;
class Directory;
class Symlink;

class THREAD_ANNOTATION_CAPABILITY("mutex") FileBase
{
private:
    static const size_t NUM_FLAGS = 7, HEADER_SIZE = 32, EXTENDED_HEADER_SIZE = 80,
                        ATIME_OFFSET = NUM_FLAGS * sizeof(uint32_t),
                        MTIME_OFFSET = ATIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t),
                        CTIME_OFFSET = MTIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t),
                        BTIME_OFFSET = CTIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t);

    static_assert(BTIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t) <= EXTENDED_HEADER_SIZE,
                  "Constants are wrong!");

private:
    securefs::Mutex m_lock;
    ptrdiff_t m_refcount;
    std::shared_ptr<HeaderBase> m_header THREAD_ANNOTATION_GUARDED_BY(*this);
    const id_type m_id;
    std::atomic<uint32_t> m_flags[NUM_FLAGS];
    fuse_timespec m_atime THREAD_ANNOTATION_GUARDED_BY(*this),
        m_mtime THREAD_ANNOTATION_GUARDED_BY(*this), m_ctime THREAD_ANNOTATION_GUARDED_BY(*this),
        m_birthtime THREAD_ANNOTATION_GUARDED_BY(*this);
    std::shared_ptr<FileStream> m_data_stream THREAD_ANNOTATION_GUARDED_BY(*this),
        m_meta_stream THREAD_ANNOTATION_GUARDED_BY(*this);
    CryptoPP::GCM<CryptoPP::AES>::Encryption m_xattr_enc THREAD_ANNOTATION_GUARDED_BY(*this);
    CryptoPP::GCM<CryptoPP::AES>::Decryption m_xattr_dec THREAD_ANNOTATION_GUARDED_BY(*this);
    bool m_dirty THREAD_ANNOTATION_GUARDED_BY(*this);
    const bool m_check, m_store_time;

private:
    void read_header() THREAD_ANNOTATION_REQUIRES(*this);

    [[noreturn]] void throw_invalid_cast(int to_type);

protected:
    std::shared_ptr<StreamBase> m_stream THREAD_ANNOTATION_GUARDED_BY(*this);

    uint32_t get_root_page() const noexcept { return m_flags[4]; }

    void set_root_page(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_flags[4] = value;
        m_dirty = true;
    }

    uint32_t get_start_free_page() const noexcept { return m_flags[5]; }

    void set_start_free_page(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_flags[5] = value;
        m_dirty = true;
    }

    uint32_t get_num_free_page() const noexcept { return m_flags[6]; }

    void set_num_free_page(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_flags[6] = value;
        m_dirty = true;
    }

    /**
     * Subclasss should override this if additional flush operations are needed
     */
    virtual void subflush() THREAD_ANNOTATION_REQUIRES(*this) {}

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

    static fuse_mode_t mode_for_type(int type) noexcept { return type << 12; }

    static int type_for_mode(fuse_mode_t mode) noexcept { return mode >> 12; }

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
                      unsigned max_padding_size,
                      bool store_time);

    virtual ~FileBase();
    DISABLE_COPY_MOVE(FileBase)

    void lock() THREAD_ANNOTATION_ACQUIRE() { m_lock.lock(); }
    void unlock() THREAD_ANNOTATION_RELEASE() { m_lock.unlock(); }
    bool try_lock() THREAD_ANNOTATION_TRY_ACQUIRE(true) { return m_lock.try_lock(); }

    void initialize_empty(uint32_t mode, uint32_t uid, uint32_t gid)
        THREAD_ANNOTATION_REQUIRES(*this);

    // --Begin of getters and setters for stats---
    uint32_t get_mode() const noexcept { return m_flags[0]; }

    void set_mode(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (get_mode() == value)
            return;
        m_flags[0] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_uid() const noexcept { return m_flags[1]; }

    void set_uid(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (get_uid() == value)
            return;
        m_flags[1] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_gid() const noexcept { return m_flags[2]; }

    void set_gid(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (get_gid() == value)
            return;
        m_flags[2] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_nlink() const noexcept { return m_flags[3]; }

    void set_nlink(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (get_nlink() == value)
            return;
        m_flags[3] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    void get_atime(fuse_timespec& out) const noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        out = m_atime;
    }

    void get_mtime(fuse_timespec& out) const noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        out = m_mtime;
    }

    void get_ctime(fuse_timespec& out) const noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        out = m_ctime;
    }

    void get_birthtime(fuse_timespec& out) const noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        out = m_birthtime;
    }

    void set_atime(const fuse_timespec& in) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_atime = in;
        m_dirty = true;
    }

    void set_mtime(const fuse_timespec& in) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_mtime = in;
        m_dirty = true;
    }

    void set_ctime(const fuse_timespec& in) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_ctime = in;
        m_dirty = true;
    }

    void update_atime_helper() THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (m_store_time && (m_atime.tv_sec < m_mtime.tv_sec || m_atime.tv_sec < m_ctime.tv_sec))
        {
            OSService::get_current_time(m_atime);
            m_dirty = true;
        }
    }

    void update_mtime_helper() THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (m_store_time)
        {
            OSService::get_current_time(m_mtime);
            m_ctime = m_mtime;
            m_dirty = true;
        }
    }

    void update_ctime_helper() THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (m_store_time)
        {
            OSService::get_current_time(m_ctime);
            m_dirty = true;
        }
    }

    // --End of getters and setters for stats---

    const id_type& get_id() const { return m_id; }

    ptrdiff_t incref() noexcept { return ++m_refcount; }

    ptrdiff_t decref() noexcept { return --m_refcount; }

    ptrdiff_t getref() const noexcept { return m_refcount; }

    void setref(ptrdiff_t value) noexcept { m_refcount = value; }

    virtual int type() const noexcept { return FileBase::BASE; }

    int get_real_type();

    bool is_unlinked() const noexcept { return get_nlink() <= 0; }

    void unlink() THREAD_ANNOTATION_REQUIRES(*this)
    {
        --m_flags[3];
        m_dirty = true;
    }

    void flush() THREAD_ANNOTATION_REQUIRES(*this);

    void fsync() THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_data_stream->fsync();
        m_meta_stream->fsync();
    }

    void utimens(const struct fuse_timespec ts[2]) THREAD_ANNOTATION_REQUIRES(*this);

    void stat(struct fuse_stat* st) THREAD_ANNOTATION_REQUIRES(*this);

    ssize_t listxattr(char* buffer, size_t size) THREAD_ANNOTATION_REQUIRES(*this);

    ssize_t getxattr(const char* name, char* value, size_t size) THREAD_ANNOTATION_REQUIRES(*this);

    void setxattr(const char* name, const char* value, size_t size, int flags)
        THREAD_ANNOTATION_REQUIRES(*this);

    void removexattr(const char* name) THREAD_ANNOTATION_REQUIRES(*this);

    template <class T>
    T* cast_as()
    {
        int type_ = type();
        if (type_ != FileBase::BASE && mode_for_type(type_) != (get_mode() & S_IFMT))
            throwFileTypeInconsistencyException();
        if (type_ != T::class_type())
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
        THREAD_ANNOTATION_REQUIRES(*this)
    {
        update_atime_helper();
        return this->m_stream->read(output, off, len);
    }

    void write(const void* input, offset_type off, length_type len)
        THREAD_ANNOTATION_REQUIRES(*this)
    {
        update_mtime_helper();
        return this->m_stream->write(input, off, len);
    }

    length_type size() const noexcept THREAD_ANNOTATION_REQUIRES(*this) { return m_stream->size(); }

    void truncate(length_type new_size) THREAD_ANNOTATION_REQUIRES(*this)
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

    std::string get() THREAD_ANNOTATION_REQUIRES(*this)
    {
        std::string result(m_stream->size(), 0);
        auto rc = m_stream->read(&result[0], 0, result.size());
        result.resize(rc);
        update_atime_helper();
        return result;
    }

    void set(const std::string& path) THREAD_ANNOTATION_REQUIRES(*this)
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
        THREAD_ANNOTATION_REQUIRES(*this)
    {
        update_atime_helper();
        return get_entry_impl(name, id, type);
    }

    bool add_entry(const std::string& name, const id_type& id, int type)
        THREAD_ANNOTATION_REQUIRES(*this)
    {
        update_mtime_helper();
        return add_entry_impl(name, id, type);
    }

    /**
     * Removes the entry while also report the info of said entry.
     * Returns false when the entry is not found.
     */
    bool remove_entry(const std::string& name, id_type& id, int& type)
        THREAD_ANNOTATION_REQUIRES(*this)
    {
        update_mtime_helper();
        return remove_entry_impl(name, id, type);
    }

    /**
     * When callback returns false, the iteration will be terminated
     */
    void iterate_over_entries(const callback& cb) THREAD_ANNOTATION_REQUIRES(*this)
    {
        update_atime_helper();
        return iterate_over_entries_impl(cb);
    }

    virtual bool empty() THREAD_ANNOTATION_REQUIRES(*this) = 0;

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
    void initialize() THREAD_ANNOTATION_REQUIRES(*this);

public:
    template <class... Args>
    explicit SimpleDirectory(Args&&... args) : Directory(std::forward<Args>(args)...)
    {
        initialize();
    }

    bool get_entry_impl(const std::string& name, id_type& id, int& type) override;

    bool add_entry_impl(const std::string& name, const id_type& id, int type) override;

    bool remove_entry_impl(const std::string& name, id_type& id, int& type) override;

    void subflush() override THREAD_ANNOTATION_REQUIRES(*this);

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

class THREAD_ANNOTATION_SCOPED_CAPABILITY FileLockGuard
{
private:
    std::lock_guard<FileBase> m_lg;

public:
    explicit FileLockGuard(FileBase& fb) THREAD_ANNOTATION_ACQUIRE(fb)
        THREAD_ANNOTATION_ACQUIRE(fb.cast_as<RegularFile>())
            THREAD_ANNOTATION_ACQUIRE(fb.cast_as<Directory>())
                THREAD_ANNOTATION_ACQUIRE(fb.cast_as<Symlink>())
        : m_lg(fb)
    {
    }
    ~FileLockGuard() THREAD_ANNOTATION_RELEASE() {}
};

class THREAD_ANNOTATION_SCOPED_CAPABILITY SpinFileLockGuard
{
private:
    std::unique_lock<FileBase> m_ul;

public:
    explicit SpinFileLockGuard(FileBase& fb) THREAD_ANNOTATION_ACQUIRE(fb)
        THREAD_ANNOTATION_ACQUIRE(fb.cast_as<RegularFile>())
            THREAD_ANNOTATION_ACQUIRE(fb.cast_as<Directory>())
                THREAD_ANNOTATION_ACQUIRE(fb.cast_as<Symlink>())
        : m_ul(fb, std::defer_lock)
    {
        for (int i = 0; i < 100; ++i)
        {
            if (m_ul.try_lock())
            {
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        throwVFSException(EBUSY);
    }
    ~SpinFileLockGuard() THREAD_ANNOTATION_RELEASE() {}
};

class THREAD_ANNOTATION_SCOPED_CAPABILITY DoubleFileLockGuard
{
private:
    std::unique_lock<FileBase> m1, m2;

public:
    explicit DoubleFileLockGuard(FileBase& f1, FileBase& f2) THREAD_ANNOTATION_ACQUIRE(f1)
        THREAD_ANNOTATION_ACQUIRE(f1.cast_as<RegularFile>())
            THREAD_ANNOTATION_ACQUIRE(f1.cast_as<Directory>())
                THREAD_ANNOTATION_ACQUIRE(f1.cast_as<Symlink>()) THREAD_ANNOTATION_ACQUIRE(f2)
                    THREAD_ANNOTATION_ACQUIRE(f2.cast_as<RegularFile>())
                        THREAD_ANNOTATION_ACQUIRE(f2.cast_as<Directory>())
                            THREAD_ANNOTATION_ACQUIRE(f2.cast_as<Symlink>())
    {
        if (&f1 == &f2)
        {
            m1 = std::unique_lock<FileBase>{f1};
        }
        else
        {
            std::lock(f1, f2);
            m1 = {f1, std::adopt_lock};
            m2 = {f2, std::adopt_lock};
        }
    }
    ~DoubleFileLockGuard() THREAD_ANNOTATION_RELEASE() {}
};
}    // namespace securefs
