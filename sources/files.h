#pragma once
#include "utils.h"
#include "streams.h"

#include <mutex>
#include <string>
#include <memory>

namespace securefs
{
class FileBase
{
private:
    std::mutex m_lock;
    std::shared_ptr<HeaderBase> m_header;
    uint32_t m_mode, m_uid, m_gid;
    uint32_t m_root_page, m_start_free_page, m_num_free_page;
    bool m_dirty;

private:
    void read_header();

protected:
    std::shared_ptr<StreamBase> m_stream;

    uint32_t get_root_page() const noexcept { return m_root_page; }
    void set_root_page(uint32_t value) noexcept
    {
        m_root_page = value;
        m_dirty = true;
    }
    uint32_t get_start_free_page() const noexcept { return m_start_free_page; }
    void set_start_free_page(uint32_t value) noexcept
    {
        m_start_free_page = value;
        m_dirty = true;
    }
    uint32_t get_num_free_page() const noexcept { return m_num_free_page; }
    void set_num_free_page(uint32_t value) noexcept
    {
        m_num_free_page = value;
        m_dirty = true;
    }

    /**
     * Subclasss should override this if additional flush operations are needed
     */
    virtual void subflush() {}

public:
    static const int REGULAR_FILE = 0, SYMLINK = 1, DIRECTORY = 2;

public:
    explicit FileBase(std::shared_ptr<StreamBase> stream, std::shared_ptr<HeaderBase> header)
        : m_stream(stream), m_header(header)
    {
        if (!m_stream || !m_header)
            NULL_EXCEPT();
        read_header();
    }
    virtual ~FileBase();
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
    DISABLE_COPY_MOVE(FileBase);

    virtual int type() const noexcept = 0;
    void flush();
};

class RegularFile : public FileBase
{
public:
    explicit RegularFile(std::shared_ptr<StreamBase> stream, std::shared_ptr<HeaderBase> header)
        : FileBase(std::move(stream), std::move(header))
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
};

class Symlink : public FileBase
{
public:
    explicit Symlink(std::shared_ptr<StreamBase> stream, std::shared_ptr<HeaderBase> header)
        : FileBase(std::move(stream), std::move(header))
    {
    }
    int type() const noexcept override { return FileBase::SYMLINK; }
    std::string get()
    {
        std::string result(m_stream->size(), 0);
        m_stream->read(&result[0], 0, result.size());
        return result;
    }
    void set(const std::string& path) { m_stream->write(path.data(), 0, path.size()); }
};

class Directory : public FileBase
{
public:
    static const size_t MAX_FILENAME_LENGTH = 255;

public:
    explicit Directory(std::shared_ptr<StreamBase> stream, std::shared_ptr<HeaderBase> header)
        : FileBase(std::move(stream), std::move(header))
    {
    }
    int type() const noexcept override { return FileBase::DIRECTORY; }

    virtual bool get_entry(const std::string& name, id_type& id, int& type) = 0;
    virtual bool add_entry(const std::string& name, const id_type& id, int type) = 0;
    virtual bool remove_entry(const std::string& name) = 0;
};

std::shared_ptr<Directory> make_directory(std::shared_ptr<StreamBase> stream,
                                          std::shared_ptr<HeaderBase> header);
}
