#pragma once

#include "crypto.h"
#include "exceptions.h"
#include "myutils.h"
#include "object.h"
#include "platform.h"
#include "streams.h"
#include "tags.h"

#include <absl/base/thread_annotations.h>
#include <absl/functional/function_ref.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rng.h>
#include <fruit/macro.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

namespace securefs
{
class RegularFile;
class Directory;
class Symlink;

class ABSL_LOCKABLE FileBase : public Object
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
    std::atomic<ptrdiff_t> m_refcount{};
    std::shared_ptr<HeaderBase> m_header ABSL_GUARDED_BY(*this);
    const id_type m_id{};
    std::atomic<uint32_t> m_flags[NUM_FLAGS]{};
    fuse_timespec m_atime ABSL_GUARDED_BY(*this){}, m_mtime ABSL_GUARDED_BY(*this){},
        m_ctime ABSL_GUARDED_BY(*this){}, m_birthtime ABSL_GUARDED_BY(*this){};
    std::shared_ptr<FileStream>
        m_data_stream ABSL_GUARDED_BY(*this){}, m_meta_stream ABSL_GUARDED_BY(*this){};
    CryptoPP::GCM<CryptoPP::AES>::Encryption m_xattr_enc ABSL_GUARDED_BY(*this){};
    CryptoPP::GCM<CryptoPP::AES>::Decryption m_xattr_dec ABSL_GUARDED_BY(*this){};
    std::optional<AES_SIV>
        m_xattr_name_cryptor;    // This class has its own mutex for thread safety.

    bool m_dirty ABSL_GUARDED_BY(*this){};
    const bool m_check{}, m_store_time{};

    // The parent_id is only used during mounting time. It doesn't get stored.
    id_type parent_id ABSL_GUARDED_BY(parent_id_mutex){};
    mutable absl::Mutex parent_id_mutex;

private:
    void read_header() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    [[noreturn]] void throw_invalid_cast(int to_type);

protected:
    std::shared_ptr<StreamBase> m_stream ABSL_GUARDED_BY(*this);

    uint32_t get_root_page() const noexcept { return m_flags[4]; }

    void set_root_page(uint32_t value) noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        m_flags[4] = value;
        m_dirty = true;
    }

    uint32_t get_start_free_page() const noexcept { return m_flags[5]; }

    void set_start_free_page(uint32_t value) noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        m_flags[5] = value;
        m_dirty = true;
    }

    uint32_t get_num_free_page() const noexcept { return m_flags[6]; }

    void set_num_free_page(uint32_t value) noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        m_flags[6] = value;
        m_dirty = true;
    }

    /**
     * Subclasss should override this if additional flush operations are needed
     */
    virtual void subflush() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) {}

public:
    static const byte REGULAR_FILE = S_IFREG >> 12, SYMLINK = S_IFLNK >> 12,
                      DIRECTORY = S_IFDIR >> 12, BASE = 255;

    static_assert(REGULAR_FILE != SYMLINK && SYMLINK != DIRECTORY,
                  "The value assigned are indistinguishable");

    virtual bool is_dirty() const ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) { return m_dirty; }

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

    void lock() ABSL_EXCLUSIVE_LOCK_FUNCTION() { m_lock.Lock(); }
    void unlock() ABSL_UNLOCK_FUNCTION() { m_lock.Unlock(); }
    bool try_lock() ABSL_EXCLUSIVE_TRYLOCK_FUNCTION(true) { return m_lock.TryLock(); }

    void initialize_empty(uint32_t mode, uint32_t uid, uint32_t gid)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    id_type get_parent_id() const noexcept
    {
        absl::MutexLock lock(&parent_id_mutex);
        return parent_id;
    }

    void set_parent_id(const id_type& value) noexcept
    {
        absl::MutexLock lock(&parent_id_mutex);
        parent_id = value;
    }

    // --Begin of getters and setters for stats---
    uint32_t get_mode() const noexcept { return m_flags[0]; }

    void set_mode(uint32_t value) noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        if (get_mode() == value)
            return;
        m_flags[0] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_uid() const noexcept { return m_flags[1]; }

    void set_uid(uint32_t value) noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        if (get_uid() == value)
            return;
        m_flags[1] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_gid() const noexcept { return m_flags[2]; }

    void set_gid(uint32_t value) noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        if (get_gid() == value)
            return;
        m_flags[2] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_nlink() const noexcept { return m_flags[3]; }

    void set_nlink(uint32_t value) noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        if (get_nlink() == value)
            return;
        m_flags[3] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    fuse_timespec get_atime() const noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        return m_atime;
    }

    fuse_timespec get_mtime() const noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        return m_mtime;
    }

    fuse_timespec get_ctime() const noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        return m_ctime;
    }

    fuse_timespec get_birthtime() const noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        return m_birthtime;
    }

    void set_atime(const fuse_timespec& in) noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        m_atime = in;
        m_dirty = true;
    }

    void set_mtime(const fuse_timespec& in) noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        m_mtime = in;
        m_dirty = true;
    }

    void set_ctime(const fuse_timespec& in) noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        m_ctime = in;
        m_dirty = true;
    }

    void update_atime_helper() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        if (m_store_time && (m_atime.tv_sec < m_mtime.tv_sec || m_atime.tv_sec < m_ctime.tv_sec))
        {
            OSService::get_current_time(m_atime);
            m_dirty = true;
        }
    }

    void update_mtime_helper() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        if (m_store_time)
        {
            OSService::get_current_time(m_mtime);
            m_ctime = m_mtime;
            m_dirty = true;
        }
    }

    void update_ctime_helper() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
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

    void unlink() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        --m_flags[3];
        m_dirty = true;
    }

    void flush() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    void fsync() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        m_data_stream->fsync();
        m_meta_stream->fsync();
    }

    void utimens(const fuse_timespec ts[2]) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    void stat(fuse_stat* st) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    ssize_t listxattr(char* buffer, size_t size) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    ssize_t getxattr(const char* name, char* value, size_t size)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    void setxattr(const char* name, const char* value, size_t size, int flags)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    void removexattr(const char* name) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

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
    constexpr static int class_type() { return FileBase::REGULAR_FILE; }

    INJECT(RegularFile(ASSISTED(std::shared_ptr<FileStream>) data_stream,
                       ASSISTED(std::shared_ptr<FileStream>) meta_stream,
                       ANNOTATED(tMasterKey, const key_type&) key_,
                       ASSISTED(const id_type&) id_,
                       ANNOTATED(tVerify, bool) check,
                       ANNOTATED(tBlockSize, unsigned) block_size,
                       ANNOTATED(tIvSize, unsigned) iv_size,
                       ANNOTATED(tMaxPaddingSize, unsigned) max_padding_size,
                       ANNOTATED(tStoreTimeWithinFs, bool) store_time))
        : FileBase(std::move(data_stream),
                   std::move(meta_stream),
                   key_,
                   id_,
                   check,
                   block_size,
                   iv_size,
                   max_padding_size,
                   store_time)
    {
    }

    RegularFile(std::shared_ptr<FileStream> data_stream,
                std::shared_ptr<FileStream> meta_stream,
                const StrongType<key_type, tMasterKey>& key_,
                const id_type& id_,
                StrongType<bool, tVerify> check,
                StrongType<unsigned, tBlockSize> block_size,
                StrongType<unsigned, tIvSize> iv_size,
                StrongType<unsigned, tMaxPaddingSize> max_padding_size,
                StrongType<bool, tStoreTimeWithinFs> store_time)
        : FileBase(std::move(data_stream),
                   std::move(meta_stream),
                   key_.get(),
                   id_,
                   check.get(),
                   block_size.get(),
                   iv_size.get(),
                   max_padding_size.get(),
                   store_time.get())
    {
    }

    int type() const noexcept override { return class_type(); }

    length_type read(void* output, offset_type off, length_type len)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        update_atime_helper();
        return this->m_stream->read(output, off, len);
    }

    void write(const void* input, offset_type off, length_type len)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        update_mtime_helper();
        return this->m_stream->write(input, off, len);
    }

    length_type size() const noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        return m_stream->size();
    }

    void truncate(length_type new_size) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        update_mtime_helper();
        return m_stream->resize(new_size);
    }
};

class Symlink : public FileBase
{
public:
    constexpr static int class_type() { return FileBase::SYMLINK; }

    INJECT(Symlink(ASSISTED(std::shared_ptr<FileStream>) data_stream,
                   ASSISTED(std::shared_ptr<FileStream>) meta_stream,
                   ANNOTATED(tMasterKey, const key_type&) key_,
                   ASSISTED(const id_type&) id_,
                   ANNOTATED(tVerify, bool) check,
                   ANNOTATED(tBlockSize, unsigned) block_size,
                   ANNOTATED(tIvSize, unsigned) iv_size,
                   ANNOTATED(tMaxPaddingSize, unsigned) max_padding_size,
                   ANNOTATED(tStoreTimeWithinFs, bool) store_time))
        : FileBase(std::move(data_stream),
                   std::move(meta_stream),
                   key_,
                   id_,
                   check,
                   block_size,
                   iv_size,
                   max_padding_size,
                   store_time)
    {
    }

    Symlink(std::shared_ptr<FileStream> data_stream,
            std::shared_ptr<FileStream> meta_stream,
            const StrongType<key_type, tMasterKey>& key_,
            const id_type& id_,
            StrongType<bool, tVerify> check,
            StrongType<unsigned, tBlockSize> block_size,
            StrongType<unsigned, tIvSize> iv_size,
            StrongType<unsigned, tMaxPaddingSize> max_padding_size,
            StrongType<bool, tStoreTimeWithinFs> store_time)
        : FileBase(std::move(data_stream),
                   std::move(meta_stream),
                   key_.get(),
                   id_,
                   check.get(),
                   block_size.get(),
                   iv_size.get(),
                   max_padding_size.get(),
                   store_time.get())
    {
    }

    int type() const noexcept override { return class_type(); }

    std::string get() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        std::string result(m_stream->size(), 0);
        auto rc = m_stream->read(&result[0], 0, result.size());
        result.resize(rc);
        update_atime_helper();
        return result;
    }

    void set(std::string_view path) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        update_mtime_helper();
        m_stream->write(path.data(), 0, path.size());
    }
};

class Directory : public FileBase
{
public:
    static const size_t MAX_FILENAME_LENGTH = 255;

public:
    constexpr static int class_type() { return FileBase::DIRECTORY; }
    using callback = absl::FunctionRef<void(const std::string&, const id_type&, int)>;

    // A wrapper for a function pointer so as to be injectable
    struct DirNameComparison
    {
        int (*fn)(std::string_view, std::string_view);

        int operator()(std::string_view a, std::string_view b) const { return fn(a, b); }
    };

    template <class... Args>
    explicit Directory(DirNameComparison cmpfn, Args&&... args)
        : FileBase(std::forward<Args>(args)...), cmpfn_(cmpfn)
    {
    }

    int type() const noexcept override { return class_type(); }

public:
    std::optional<std::string_view> get_entry(std::string_view name, id_type& id, int& type)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        update_atime_helper();
        return get_entry_impl(name, id, type);
    }

    bool add_entry(std::string_view name, const id_type& id, int type)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        update_mtime_helper();
        return add_entry_impl(name, id, type);
    }

    /**
     * Removes the entry while also report the info of said entry.
     * Returns false when the entry is not found.
     */
    bool remove_entry(std::string_view name, id_type& id, int& type)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        update_mtime_helper();
        return remove_entry_impl(name, id, type);
    }

    /**
     * When callback returns false, the iteration will be terminated
     */
    void iterate_over_entries(const callback& cb) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        update_atime_helper();
        return iterate_over_entries_impl(cb);
    }

    virtual bool empty() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this) = 0;

protected:
    virtual std::optional<std::string_view>
    get_entry_impl(std::string_view name, id_type& id, int& type) = 0;

    virtual bool add_entry_impl(std::string_view name, const id_type& id, int type) = 0;

    /**
     * Removes the entry while also report the info of said entry.
     * Returns false when the entry is not found.
     */
    virtual bool remove_entry_impl(std::string_view name, id_type& id, int& type) = 0;

    /**
     * When callback returns false, the iteration will be terminated
     */
    virtual void iterate_over_entries_impl(const callback& cb) = 0;

protected:
    DirNameComparison cmpfn_;
};

class SimpleDirectory final : public Directory
{
private:
    struct Less
    {
        using is_transparent = void;

        DirNameComparison cmpfn;

        bool operator()(std::string_view a, std::string_view b) const { return cmpfn(a, b) < 0; }
    };

    std::map<std::string, std::pair<id_type, int>, Less> m_table{Less{this->cmpfn_}};
    bool m_dirty;

private:
    void initialize() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

public:
    template <class... Args>
    explicit SimpleDirectory(Args&&... args) : Directory(std::forward<Args>(args)...)
    {
        initialize();
    }

    std::optional<std::string_view>
    get_entry_impl(std::string_view name, id_type& id, int& type) override;

    bool add_entry_impl(std::string_view name, const id_type& id, int type) override;

    bool remove_entry_impl(std::string_view name, id_type& id, int& type) override;

    void subflush() override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    void iterate_over_entries_impl(const callback& cb) override
    {
        for (const auto& pair : m_table)
        {
            cb(pair.first, pair.second.first, pair.second.second);
        }
    }

    bool empty() noexcept override { return m_table.empty(); }

    ~SimpleDirectory();
};

class ABSL_SCOPED_LOCKABLE FileLockGuard
{
private:
    std::lock_guard<FileBase> m_lg;

public:
    explicit FileLockGuard(FileBase& fb) ABSL_EXCLUSIVE_LOCK_FUNCTION(fb)
        ABSL_EXCLUSIVE_LOCK_FUNCTION(fb.cast_as<RegularFile>())
            ABSL_EXCLUSIVE_LOCK_FUNCTION(fb.cast_as<Directory>())
                ABSL_EXCLUSIVE_LOCK_FUNCTION(fb.cast_as<Symlink>())
        : m_lg(fb)
    {
    }
    ~FileLockGuard() ABSL_UNLOCK_FUNCTION() {}
};

class ABSL_SCOPED_LOCKABLE SpinFileLockGuard
{
private:
    std::unique_lock<FileBase> m_ul;

public:
    explicit SpinFileLockGuard(FileBase& fb) ABSL_EXCLUSIVE_LOCK_FUNCTION(fb)
        ABSL_EXCLUSIVE_LOCK_FUNCTION(fb.cast_as<RegularFile>())
            ABSL_EXCLUSIVE_LOCK_FUNCTION(fb.cast_as<Directory>())
                ABSL_EXCLUSIVE_LOCK_FUNCTION(fb.cast_as<Symlink>())
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
    ~SpinFileLockGuard() ABSL_UNLOCK_FUNCTION() {}
};

class ABSL_SCOPED_LOCKABLE DoubleFileLockGuard
{
private:
    std::unique_lock<FileBase> m1, m2;

public:
    explicit DoubleFileLockGuard(FileBase& f1, FileBase& f2) ABSL_EXCLUSIVE_LOCK_FUNCTION(f1)
        ABSL_EXCLUSIVE_LOCK_FUNCTION(f1.cast_as<RegularFile>())
            ABSL_EXCLUSIVE_LOCK_FUNCTION(f1.cast_as<Directory>())
                ABSL_EXCLUSIVE_LOCK_FUNCTION(f1.cast_as<Symlink>()) ABSL_EXCLUSIVE_LOCK_FUNCTION(f2)
                    ABSL_EXCLUSIVE_LOCK_FUNCTION(f2.cast_as<RegularFile>())
                        ABSL_EXCLUSIVE_LOCK_FUNCTION(f2.cast_as<Directory>())
                            ABSL_EXCLUSIVE_LOCK_FUNCTION(f2.cast_as<Symlink>())
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
    ~DoubleFileLockGuard() ABSL_UNLOCK_FUNCTION() {}
};
}    // namespace securefs
