#pragma once
#include "files.h"
#include "streams.h"
#include "utils.h"
#include "exceptions.h"

#include <memory>
#include <unordered_map>
#include <algorithm>
#include <utility>
#include <mutex>

namespace securefs
{
class FileTable
{
private:
    class id_hash
    {
    private:
        size_t m_seed;

    public:
        id_hash();
        size_t operator()(const id_type&) const noexcept;
    };

    typedef std::unordered_map<id_type, std::unique_ptr<FileBase>, id_hash> table_type;

    table_type m_opened, m_closed;
    std::mutex m_lock;
    int m_dir_fd;

public:
    explicit FileTable(int dir_fd) : m_dir_fd(dir_fd) {}
    void lock() { m_lock.lock(); }
    void unlock() { m_lock.unlock(); }
    FileBase* open_as(const id_type& id, int type);
    FileBase* create_as(const id_type& id, int type);
    void close(FileBase*);
};
}
