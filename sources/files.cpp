#include "files.h"

#include <unordered_map>
#include <utility>
#include <algorithm>

namespace securefs
{
void FileBase::read_header()
{
    byte header[sizeof(m_flags)];
    auto rc = m_header->read_header(header, sizeof(header));
    if (!rc)
    {
        memset(m_flags, 0xFF, sizeof(m_flags));
    }
    else
    {
        const byte* ptr = header;
        for (auto&& f : m_flags)
        {
            f = from_little_endian<decltype(f)>(ptr);
            ptr += sizeof(f);
        }
    }
}

FileBase::~FileBase() {}

void FileBase::flush()
{
    this->subflush();
    if (m_dirty)
    {
        byte header[sizeof(m_flags)];
        byte* ptr = header;
        for (auto&& f : m_flags)
        {
            to_little_endian(f, ptr);
            ptr += sizeof(f);
        }
        m_header->write_header(header, sizeof(header));
        m_dirty = false;
    }
    m_header->flush_header();
    m_stream->flush();
}

namespace internal
{
    class SimpleDirectory : public Directory
    {
    private:
        std::unordered_map<std::string, std::pair<id_type, int>> m_table;
        bool m_dirty;

    public:
        explicit SimpleDirectory(std::shared_ptr<StreamBase> stream,
                                 std::shared_ptr<HeaderBase> header)
            : Directory(std::move(stream), std::move(header)), m_dirty(false)
        {
            char buffer[Directory::MAX_FILENAME_LENGTH + 1 + 32 + 4];
            offset_type off = 0;
            std::string name;
            std::pair<id_type, int> value;
            while (true)
            {
                auto rv = this->m_stream->read(buffer, off, sizeof(buffer));
                if (rv < sizeof(buffer))
                    break;
                buffer[MAX_FILENAME_LENGTH]
                    = 0;    // Set the null terminator in case the data is corrupted
                name = buffer;
                memcpy(value.first.data(), buffer + Directory::MAX_FILENAME_LENGTH + 1, ID_LENGTH);
                value.second
                    = from_little_endian<uint32_t>(buffer + sizeof(buffer) - sizeof(uint32_t));
                m_table.emplace(std::move(name), std::move(value));
                off += sizeof(buffer);
            }
        }

        bool get_entry(const std::string& name, id_type& id, int& type) override
        {
            auto it = m_table.find(name);
            if (it == m_table.end())
                return false;
            memcpy(id.data(), it->second.first.data(), id.size());
            type = it->second.second;
            return true;
        }

        bool add_entry(const std::string& name, const id_type& id, int type) override
        {
            if (name.size() > MAX_FILENAME_LENGTH)
                throw OSException(ENAMETOOLONG);
            auto rv = m_table.emplace(name, std::make_pair(id, type));
            if (rv.second)
                m_dirty = true;
            return rv.second;
        }

        bool remove_entry(const std::string& name, id_type& id, int& type) override
        {
            auto it = m_table.find(name);
            if (it == m_table.end())
                return false;
            memcpy(id.data(), it->second.first.data(), id.size());
            type = it->second.second;
            m_table.erase(it);
            m_dirty = true;
            return true;
        }

        void subflush() override
        {
            if (m_dirty)
            {
                char buffer[Directory::MAX_FILENAME_LENGTH + 1 + 32 + 4];
                offset_type off = 0;
                for (auto&& pair : m_table)
                {
                    memset(buffer, 0, sizeof(buffer));
                    if (pair.first.size() > MAX_FILENAME_LENGTH)
                        continue;
                    memcpy(buffer, pair.first.data(), pair.first.size());
                    memcpy(buffer + MAX_FILENAME_LENGTH + 1, pair.second.first.data(), ID_LENGTH);
                    to_little_endian(static_cast<uint32_t>(pair.second.second),
                                     buffer + sizeof(buffer) - sizeof(uint32_t));
                    this->m_stream->write(buffer, off, sizeof(buffer));
                    off += sizeof(buffer);
                }
                m_dirty = false;
            }
        }

        void iterate_over_entries(callback cb) override
        {
            for (const auto& pair : m_table)
            {
                if (!cb(pair.first, pair.second.first, pair.second.second))
                    break;
            }
        }

        bool empty() const override { return m_table.empty(); }

        ~SimpleDirectory()
        {
            try
            {
                flush();
            }
            catch (...)
            {
                // Ignore exceptions in destructor
            }
        }
    };
}

std::shared_ptr<Directory> make_directory(std::shared_ptr<StreamBase> stream,
                                          std::shared_ptr<HeaderBase> header)
{
    return std::make_shared<internal::SimpleDirectory>(std::move(stream), std::move(header));
}
}
