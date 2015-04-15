#include "files.h"

#include <unordered_map>
#include <utility>
#include <algorithm>

namespace securefs
{
void FileBase::read_header()
{
    byte header[sizeof(m_mode) + sizeof(m_uid) + sizeof(m_gid) + sizeof(m_root_page)
                + sizeof(m_start_free_page) + sizeof(m_num_free_page)];
    auto rc = m_header->read_header(header, sizeof(header));
    if (!rc)
    {
        m_mode = 0;
        m_uid = 0;
        m_gid = 0;
        m_root_page = 0;
        m_start_free_page = 0;
        m_num_free_page = 0;
    }
    else
    {
        const byte* ptr = header;
        m_mode = from_little_endian<decltype(m_mode)>(ptr);
        ptr += sizeof(m_mode);
        m_uid = from_little_endian<decltype(m_uid)>(ptr);
        ptr += sizeof(m_uid);
        m_gid = from_little_endian<decltype(m_gid)>(ptr);
        ptr += sizeof(m_gid);
        m_root_page = from_little_endian<decltype(m_root_page)>(ptr);
        ptr += sizeof(m_root_page);
        m_start_free_page = from_little_endian<decltype(m_start_free_page)>(ptr);
        ptr += sizeof(m_start_free_page);
        m_num_free_page = from_little_endian<decltype(m_num_free_page)>(ptr);
        ptr += sizeof(m_num_free_page);
    }
}

FileBase::~FileBase() {}

void FileBase::flush()
{
    if (m_dirty)
    {
        byte header[sizeof(m_mode) + sizeof(m_uid) + sizeof(m_gid) + sizeof(m_root_page)
                    + sizeof(m_start_free_page) + sizeof(m_num_free_page)];

        m_dirty = false;
    }
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

        bool remove_entry(const std::string& name) override
        {
            auto count = m_table.erase(name);
            if (count > 0)
                m_dirty = true;
            return count > 0;
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
