#include "btree_dir.h"

#include <vector>
#include <algorithm>
#include <utility>
#include <type_traits>

namespace
{
const uint32_t INVALID_PAGE = -1;
const int MAX_DEPTH = 32;
}

namespace securefs
{

class CorruptedDirectoryException : public SeriousException
{
public:
    const char* type_name() const noexcept override { return "CorruptedDirectoryException"; }
    std::string message() const override { return "Directory corrupted"; }
};

template <class T>
static const byte* read_and_forward(const byte* buffer, const byte* end, T& value)
{
    static_assert(std::is_trivially_copyable<T>::value, "");
    if (buffer + sizeof(value) > end)
        throw CorruptedDirectoryException();
    memcpy(&value, buffer, sizeof(value));
    return buffer + sizeof(value);
}

template <class T>
static byte* write_and_forward(const T& value, byte* buffer, const byte* end)
{
    static_assert(std::is_trivially_copyable<T>::value, "");
    if (buffer + sizeof(value) > end)
        throw CorruptedDirectoryException();
    memcpy(buffer, &value, sizeof(value));
    return buffer + sizeof(value);
}

template <class T>
static T read_little_endian_and_forward(const byte** buffer, const byte* end)
{
    if (*buffer + sizeof(T) > end)
        throw CorruptedDirectoryException();
    auto v = from_little_endian<T>(*buffer);
    *buffer += sizeof(T);
    return v;
}

template <class T>
static byte* write_little_endian_and_forward(const T& value, byte* buffer, const byte* end)
{
    if (buffer + sizeof(T) > end)
        throw CorruptedDirectoryException();
    to_little_endian(value, buffer);
    return buffer + sizeof(T);
}

class BtreeDirectory::Entry
{
public:
    std::array<char, BtreeDirectory::MAX_FILENAME_LENGTH + 1> filename;
    id_type id;
    byte type;

    int compare(const Entry& other) const { return strcmp(filename.data(), other.filename.data()); }
    int compare(const std::string& name) const { return strcmp(filename.data(), name.c_str()); }
    bool operator<(const Entry& other) const { return compare(other) < 0; }
    bool operator==(const Entry& other) const { return compare(other) == 0; }
    bool operator<(const std::string& other) const { return compare(other) < 0; }
    bool operator==(const std::string& other) const { return compare(other) == 0; }
};

class BtreeDirectory::Node
{
public:
    std::vector<uint32_t> child_indices;
    std::vector<Entry> entries;

public:
    void from_buffer(const byte* buffer, size_t size)
    {
        const byte* end_of_buffer = buffer + size;

        auto flag = read_little_endian_and_forward<uint32_t>(&buffer, end_of_buffer);
        if (flag == 0)
            throw CorruptedDirectoryException();
        auto child_num = read_little_endian_and_forward<uint16_t>(&buffer, end_of_buffer);
        auto entry_num = read_little_endian_and_forward<uint16_t>(&buffer, end_of_buffer);

        for (uint16_t i = 0; i < child_num; ++i)
        {
            child_indices.push_back(
                read_little_endian_and_forward<uint32_t>(&buffer, end_of_buffer));
        }
        Entry e;
        for (uint16_t i = 0; i < entry_num; ++i)
        {
            buffer = read_and_forward(buffer, end_of_buffer, e.filename);
            buffer = read_and_forward(buffer, end_of_buffer, e.id);
            buffer = read_and_forward(buffer, end_of_buffer, e.type);
            e.filename.back() = 0;    // In case it is not null terminated.
            entries.push_back(e);
        }
    }

    void to_buffer(byte* buffer, size_t size) const
    {
        const byte* end_of_buffer = buffer + size;
        buffer = write_little_endian_and_forward(static_cast<uint32_t>(1), buffer, end_of_buffer);
        buffer = write_little_endian_and_forward(
            static_cast<uint16_t>(child_indices.size()), buffer, end_of_buffer);
        buffer = write_little_endian_and_forward(
            static_cast<uint16_t>(entries.size()), buffer, end_of_buffer);

        for (uint32_t index : child_indices)
        {
            buffer = write_little_endian_and_forward(index, buffer, end_of_buffer);
        }

        for (auto&& e : entries)
        {
            buffer = write_and_forward(e.filename, buffer, end_of_buffer);
            buffer = write_and_forward(e.id, buffer, end_of_buffer);
            buffer = write_and_forward(e.type, buffer, end_of_buffer);
        }
    }
};

void BtreeDirectory::read_node(uint32_t num, BtreeDirectory::Node& n)
{
    byte buffer[BLOCK_SIZE];
    if (m_stream->read(buffer, num * BLOCK_SIZE, BLOCK_SIZE) != BLOCK_SIZE)
        throw CorruptedDirectoryException();
    n.from_buffer(buffer, sizeof(buffer));
}

void BtreeDirectory::write_node(uint32_t num, const BtreeDirectory::Node& n)
{
    byte buffer[BLOCK_SIZE];
    n.to_buffer(buffer, sizeof(buffer));
    m_stream->write(buffer, num * BLOCK_SIZE, BLOCK_SIZE);
}

bool BtreeDirectory::get_entry(const std::string& name, id_type& id, int& type)
{
    if (name.size() > MAX_FILENAME_LENGTH)
        throw OSException(ENAMETOOLONG);

    auto page = get_root_page();
    if (page == INVALID_PAGE)
        return false;

    Node n;

    for (int i = 0; i < MAX_DEPTH; ++i)
    {
        read_node(page, n);
        auto iter = std::lower_bound(n.entries.begin(), n.entries.end(), name);
        if (iter != n.entries.end() && iter->compare(name) == 0)
        {
            id = iter->id;
            type = iter->type;
            return true;
        }

        size_t child = iter - n.entries.begin();
        if (child >= n.child_indices.size())
            return false;

        read_node(n.child_indices[child], n);
    }
    throw CorruptedDirectoryException();    // The operation is stuck in an infinite loop
}

bool BtreeDirectory::add_entry(const std::string& name, const id_type& id, int type)
{
    if (name.size() > MAX_FILENAME_LENGTH)
        throw OSException(ENAMETOOLONG);

    auto page = get_root_page();
    if (page == INVALID_PAGE)
        return false;

    Node n;

    for (int i = 0; i < MAX_DEPTH; ++i)
    {
        read_node(page, n);
        auto iter = std::lower_bound(n.entries.begin(), n.entries.end(), name);
        if (iter != n.entries.end() && iter->compare(name) == 0)
            return false;

        size_t child = iter - n.entries.begin();
        if (child >= n.child_indices.size())
        {
        }

        read_node(n.child_indices[child], n);
    }
    throw CorruptedDirectoryException();    // The operation is stuck in an infinite loop
}
}
