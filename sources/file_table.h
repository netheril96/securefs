#pragma once
#include "exceptions.h"
#include "files.h"
#include "streams.h"
#include "utils.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <queue>
#include <string.h>
#include <unordered_map>
#include <utility>

namespace securefs
{
class FileTableIO;

class FileTable
{
    DISABLE_COPY_MOVE(FileTable);

private:
    struct id_hash
    {
        size_t operator()(const id_type&) const noexcept;
    };

    typedef std::unordered_map<id_type, std::shared_ptr<FileBase>, id_hash> table_type;

private:
    static const int MAX_NUM_CLOSED = 128, NUM_EJECT = 8;

private:
    key_type m_master_key;
    table_type m_opened, m_closed;
    std::queue<id_type> m_closed_ids;
    std::unique_ptr<FileTableIO> m_fio;
    uint32_t m_flags;
    unsigned m_block_size, m_iv_size;

private:
    void eject();
    void finalize(FileBase*);

public:
    static const uint32_t READ_ONLY = 0x1, NO_AUTHENTICATION = 0x2;

public:
    explicit FileTable(int dir_fd,
                       const key_type& master_key,
                       uint32_t flags,
                       unsigned block_size,
                       unsigned iv_size);
    ~FileTable();
    FileBase* open_as(const id_type& id, int type);
    FileBase* create_as(const id_type& id, int type);
    void close(FileBase*);
    bool is_readonly() const noexcept { return m_flags & READ_ONLY; }
    bool is_auth_enabled() const noexcept { return !(m_flags & NO_AUTHENTICATION); }
    void gc();
};
}
