#pragma once
#include "utils.h"
#include "streams.h"

#include <mutex>
#include <string>
#include <memory>

namespace securefs
{

class Filebase
{
private:
    std::mutex m_lock;
    std::shared_ptr<HeaderBase> m_header;
    std::shared_ptr<StreamBase> m_stream;
    uint32_t m_mode, m_uid, m_gid;
    uint32_t m_root_page, m_free_page;
    bool m_dirty;

private:
    void read_header();

protected:
    uint32_t get_root_page() const noexcept { return m_root_page; }
    void set_root_page(uint32_t value) noexcept
    {
        m_root_page = value;
        m_dirty = true;
    }
    uint32_t get_free_page() const noexcept { return m_free_page; }
    void set_free_page(uint32_t value) noexcept
    {
        m_free_page = value;
        m_dirty = true;
    }

    /**
     * Subclasss should override this if additional flush operations are needed
     */
    virtual void subflush() {}

public:
    static const int REGULAR_FILE = 0, SYMLINK = 1, DIRECTORY = 2;

public:
    explicit Filebase(std::shared_ptr<StreamBase> stream, std::shared_ptr<HeaderBase> header)
        : m_stream(stream), m_header(header)
    {
        read_header();
    }
    virtual ~Filebase() {}
    uint32_t get_mode() const noexcept { return m_mode; }
    void set_mode(uint32_t value) noexcept
    {
        m_mode = value;
        m_dirty = true;
    }
    uint32_t get_uid() const noexcept { return m_uid; }
    void set_uid(uint32_t value) noexcept
    {
        m_uid = value;
        m_dirty = true;
    }
    uint32_t get_gid() const noexcept { return m_gid; }
    void set_gid(uint32_t value) noexcept
    {
        m_gid = value;
        m_dirty = true;
    }
    DISABLE_COPY_MOVE(Filebase);

    virtual int type() const noexcept = 0;
    void flush();
};
}
