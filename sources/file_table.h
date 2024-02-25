#pragma once
#include "constants.h"
#include "exceptions.h"
#include "files.h"
#include "myutils.h"
#include "platform.h"
#include "streams.h"

#include <absl/base/thread_annotations.h>
#include <absl/container/flat_hash_map.h>

#include <memory>
#include <string.h>
#include <utility>

namespace securefs
{
class FileTableIO;

class AutoClosedFileBase;

class FileTable
{
public:
    FileTable() {}
    virtual ~FileTable();

    virtual FileBase* open_as(const id_type& id, int type) = 0;
    virtual FileBase* create_as(const id_type& id, int type) = 0;
    virtual void close(FileBase*) = 0;
    virtual bool is_readonly() const noexcept = 0;
    virtual bool is_auth_enabled() const noexcept = 0;
    virtual bool is_time_stored() const noexcept = 0;
    virtual void statfs(struct fuse_statvfs* fs_info) = 0;
    virtual bool has_padding() const noexcept = 0;
};

class FileTableImpl final : public FileTable
{
private:
    typedef absl::flat_hash_map<id_type, std::unique_ptr<FileBase>, id_hash> table_type;

private:
    static const int MAX_NUM_CLOSED = 101, NUM_EJECT = 8;

private:
    securefs::Mutex m_lock;
    key_type m_master_key;
    table_type m_files ABSL_GUARDED_BY(m_lock);
    std::vector<id_type> m_closed_ids ABSL_GUARDED_BY(m_lock);
    std::unique_ptr<FileTableIO> m_fio ABSL_GUARDED_BY(m_lock);
    uint32_t m_flags;
    unsigned m_block_size, m_iv_size, m_max_padding_size;
    std::shared_ptr<const OSService> m_root;

private:
    void eject() ABSL_EXCLUSIVE_LOCKS_REQUIRED(m_lock);
    void finalize(std::unique_ptr<FileBase>&) ABSL_EXCLUSIVE_LOCKS_REQUIRED(m_lock);
    void gc() ABSL_EXCLUSIVE_LOCKS_REQUIRED(m_lock);

public:
    explicit FileTableImpl(int version,
                           std::shared_ptr<const OSService> root,
                           const key_type& master_key,
                           uint32_t flags,
                           unsigned block_size,
                           unsigned iv_size,
                           unsigned max_padding_size);
    ~FileTableImpl();
    FileBase* open_as(const id_type& id, int type) override;
    FileBase* create_as(const id_type& id, int type) override;
    void close(FileBase*) override;
    bool is_readonly() const noexcept override { return (m_flags & kOptionReadOnly) != 0; }
    bool is_auth_enabled() const noexcept override
    {
        return (m_flags & kOptionNoAuthentication) == 0;
    }
    bool is_time_stored() const noexcept override { return (m_flags & kOptionStoreTime) != 0; }
    void statfs(struct fuse_statvfs* fs_info) override { m_root->statfs(fs_info); }
    bool has_padding() const noexcept override { return m_max_padding_size > 0; }
};

class ShardedFileTableImpl final : public FileTable
{
private:
    std::vector<std::unique_ptr<FileTableImpl>> m_shards;

    FileTableImpl* get_shard_by_id(const id_type& id) noexcept;

public:
    explicit ShardedFileTableImpl(int version,
                                  std::shared_ptr<const OSService> root,
                                  const key_type& master_key,
                                  uint32_t flags,
                                  unsigned block_size,
                                  unsigned iv_size,
                                  unsigned max_padding_size);
    ~ShardedFileTableImpl();
    FileBase* open_as(const id_type& id, int type) override;
    FileBase* create_as(const id_type& id, int type) override;
    void close(FileBase* fb) override;
    bool is_readonly() const noexcept override { return m_shards.back()->is_readonly(); }
    bool is_auth_enabled() const noexcept override { return m_shards.back()->is_auth_enabled(); }
    bool is_time_stored() const noexcept override { return m_shards.back()->is_time_stored(); }
    void statfs(struct fuse_statvfs* fs_info) override { return m_shards.back()->statfs(fs_info); }
    bool has_padding() const noexcept override { return m_shards.back()->has_padding(); }
};

class AutoClosedFileBase
{
private:
    FileTable* m_ft;
    FileBase* m_fb;

public:
    explicit AutoClosedFileBase(FileTable* ft, FileBase* fb) : m_ft(ft), m_fb(fb) {}

    AutoClosedFileBase(const AutoClosedFileBase&) = delete;
    AutoClosedFileBase& operator=(const AutoClosedFileBase&) = delete;

    AutoClosedFileBase(AutoClosedFileBase&& other) noexcept : m_ft(other.m_ft), m_fb(other.m_fb)
    {
        other.m_ft = nullptr;
        other.m_fb = nullptr;
    }

    AutoClosedFileBase& operator=(AutoClosedFileBase&& other) noexcept
    {
        if (this == &other)
            return *this;
        swap(other);
        return *this;
    }

    ~AutoClosedFileBase()
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
        return m_fb->cast_as<T>();
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
            m_ft->close(m_fb);
        }
        m_fb = fb;
    }
    void swap(AutoClosedFileBase& other) noexcept
    {
        std::swap(m_ft, other.m_ft);
        std::swap(m_fb, other.m_fb);
    }
};

inline AutoClosedFileBase open_as(FileTable& table, const id_type& id, int type)
{
    return AutoClosedFileBase(&table, table.open_as(id, type));
}

inline AutoClosedFileBase create_as(FileTable& table, const id_type& id, int type)
{
    return AutoClosedFileBase(&table, table.create_as(id, type));
}
}    // namespace securefs
