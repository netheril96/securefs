#pragma once
#include "files.h"
#include "myutils.h"
#include "object.h"
#include "platform.h"
#include "tags.h"

#include <absl/base/thread_annotations.h>
#include <absl/container/flat_hash_map.h>

#include <array>
#include <cstddef>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace securefs::full_format
{
using FileStreamPtrPair = std::pair<std::shared_ptr<FileStream>, std::shared_ptr<FileStream>>;

const inline id_type kRootId{};

class FileTableIO : public Object
{
public:
    virtual FileStreamPtrPair open(const id_type& id) = 0;
    virtual FileStreamPtrPair create(const id_type& id) = 0;
    virtual void unlink(const id_type& id) noexcept = 0;
};

std::shared_ptr<FileTableIO> make_table_io(std::shared_ptr<OSService> os_service,
                                           StrongType<bool, tLegacy> legacy,
                                           StrongType<bool, tReadOnly> readonly);

class FileTable;
class FileTableCloser;

using FilePtrHolder = std::unique_ptr<FileBase, FileTableCloser>;

class FileTable
{
public:
    template <class T>
    using Factory = std::function<std::unique_ptr<T>(
        std::shared_ptr<FileStream>, std::shared_ptr<FileStream>, const id_type&)>;

public:
    FileTable(std::shared_ptr<FileTableIO> io,
                     Factory<RegularFile> regular_file_factory,
                     Factory<Directory> directory_factory,
                     Factory<Symlink> symlink_factory)
        : io_(std::move(io))
        , regular_file_factory_(std::move(regular_file_factory))
        , directory_factory_(std::move(directory_factory))
        , symlink_factory_(std::move(symlink_factory))
    {
        init();
    }
    ~FileTable();
    FilePtrHolder open_as(const id_type& id, int type);
    FilePtrHolder create_as(int type);
    void close(const id_type& id);

private:
    struct Shard
    {
        Mutex mu;
        absl::flat_hash_map<id_type, std::unique_ptr<FileBase>, id_hash>
            live_map ABSL_GUARDED_BY(mu);
        std::vector<std::unique_ptr<FileBase>> cache ABSL_GUARDED_BY(mu);
    };
    static constexpr inline size_t kNumShards = 32, kMaxCached = 50, kEjectNumber = 10;

    void init();
    Shard& find_shard(const id_type& id);
    std::unique_ptr<FileBase> construct(int type,
                                        std::shared_ptr<FileStream> data_stream,
                                        std::shared_ptr<FileStream> meta_stream,
                                        const id_type& id);
    void close_internal(const id_type id);
    FilePtrHolder create_holder(FileBase* fb);
    FilePtrHolder create_holder(std::unique_ptr<FileBase>& fb);

private:
    std::shared_ptr<FileTableIO> io_;
    std::unique_ptr<FileBase> root_;
    Factory<RegularFile> regular_file_factory_;
    Factory<Directory> directory_factory_;
    Factory<Symlink> symlink_factory_;
    std::array<Shard, kNumShards> shards{};
};

class FileTableCloser
{
public:
    explicit FileTableCloser(FileTable* table) : table_(table) {}

    void operator()(FileBase* fb) const;

private:
    FileTable* table_;
};
}    // namespace securefs::full_format
