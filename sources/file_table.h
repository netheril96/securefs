#pragma once
#include "files.h"
#include "streams.h"
#include "utils.h"
#include "exceptions.h"

#include <chrono>
#include <memory>
#include <map>
#include <algorithm>
#include <utility>
#include <string.h>
#include <random>

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

    typedef std::map<id_type, std::shared_ptr<FileBase>> table_type;

private:
    static const size_t MAX_NUM_CLOSED = 50, NUM_EJECT = 5;

private:
    key_type m_master_key;
    table_type m_opened, m_closed;
    uint64_t m_counter;
    int m_dir_fd;
    uint32_t m_flags;
    std::mt19937 m_rng;

private:
    void eject();
    void finalize(FileBase*);

public:
    static const uint32_t READ_ONLY = 0x1, NO_AUTHENTICATION = 0x2;

public:
    explicit FileTable(int dir_fd, const key_type& master_key, uint32_t flags)
        : m_counter(0), m_dir_fd(dir_fd), m_flags(flags), m_rng(std::random_device()())
    {
        memcpy(m_master_key.data(), master_key.data(), master_key.size());
    }
    ~FileTable();
    FileBase* open_as(const id_type& id, int type);
    FileBase* create_as(const id_type& id, int type);
    void close(FileBase*);
    bool is_readonly() const noexcept { return m_flags & READ_ONLY; }
    bool is_auth_enabled() const noexcept { return !(m_flags & NO_AUTHENTICATION); }
    std::vector<std::shared_ptr<FileBase>> all_files() const;
};
}
