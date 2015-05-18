#include "btree_dir.h"

#include <vector>
#include <algorithm>
#include <utility>
#include <type_traits>
#include <assert.h>

namespace securefs
{
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

class BtreeDirectory::FreePage
{
public:
    uint32_t next;
    uint32_t prev;
};

void BtreeDirectory::read_free_page(uint32_t num, FreePage& fp)
{
    byte buffer[BLOCK_SIZE];
    if (m_stream->read(buffer, num * BLOCK_SIZE, BLOCK_SIZE) != BLOCK_SIZE)
        throw CorruptedDirectoryException();
    if (from_little_endian<uint32_t>(buffer) != 0)
        throw CorruptedDirectoryException();
    fp.next = from_little_endian<uint32_t>(buffer + sizeof(uint32_t));
    fp.prev = from_little_endian<uint32_t>(buffer + sizeof(uint32_t) * 2);
}

void BtreeDirectory::write_free_page(uint32_t num, const FreePage& fp)
{
    byte buffer[BLOCK_SIZE] = {};
    to_little_endian(fp.next, buffer + sizeof(uint32_t));
    to_little_endian(fp.prev, buffer + sizeof(uint32_t) * 2);
    m_stream->write(buffer, BLOCK_SIZE * num, BLOCK_SIZE);
}

uint32_t BtreeDirectory::allocate_page()
{
    auto pg = get_start_free_page();
    if (pg == INVALID_PAGE)
    {
        auto result = static_cast<uint32_t>(m_stream->size() / BLOCK_SIZE);
        m_stream->resize(m_stream->size() + BLOCK_SIZE);
        return result;
    }
    FreePage fp;
    read_free_page(pg, fp);
    set_num_free_page(get_num_free_page() - 1);
    set_start_free_page(fp.next);
    read_free_page(fp.next, fp);
    fp.prev = INVALID_PAGE;
    write_free_page(get_start_free_page(), fp);
    return pg;
}

void BtreeDirectory::deallocate_page(uint32_t num)
{
    FreePage fp;
    fp.prev = INVALID_PAGE;
    fp.next = get_start_free_page();
    write_free_page(num, fp);
    read_free_page(get_start_free_page(), fp);
    fp.prev = num;
    write_free_page(get_start_free_page(), fp);
    set_start_free_page(num);
    set_num_free_page(get_num_free_page() + 1);
}

void BtreeNode::from_buffer(const byte* buffer, size_t size)
{
    const byte* end_of_buffer = buffer + size;

    auto flag = read_little_endian_and_forward<uint32_t>(&buffer, end_of_buffer);
    if (flag == 0)
        throw CorruptedDirectoryException();
    auto child_num = read_little_endian_and_forward<uint16_t>(&buffer, end_of_buffer);
    auto entry_num = read_little_endian_and_forward<uint16_t>(&buffer, end_of_buffer);

    for (uint16_t i = 0; i < child_num; ++i)
    {
        m_child_indices.push_back(read_little_endian_and_forward<uint32_t>(&buffer, end_of_buffer));
    }
    DirEntry e;
    for (uint16_t i = 0; i < entry_num; ++i)
    {
        buffer = read_and_forward(buffer, end_of_buffer, e.filename);
        buffer = read_and_forward(buffer, end_of_buffer, e.id);
        buffer = read_and_forward(buffer, end_of_buffer, e.type);
        e.filename.back() = 0;    // In case it is not null terminated.
        m_entries.push_back(e);
    }
}

void BtreeNode::to_buffer(byte* buffer, size_t size) const
{
    const byte* end_of_buffer = buffer + size;
    buffer = write_little_endian_and_forward(static_cast<uint32_t>(1), buffer, end_of_buffer);
    buffer = write_little_endian_and_forward(
        static_cast<uint16_t>(m_child_indices.size()), buffer, end_of_buffer);
    buffer = write_little_endian_and_forward(
        static_cast<uint16_t>(m_entries.size()), buffer, end_of_buffer);

    for (uint32_t index : m_child_indices)
    {
        buffer = write_little_endian_and_forward(index, buffer, end_of_buffer);
    }

    for (auto&& e : m_entries)
    {
        buffer = write_and_forward(e.filename, buffer, end_of_buffer);
        buffer = write_and_forward(e.id, buffer, end_of_buffer);
        buffer = write_and_forward(e.type, buffer, end_of_buffer);
    }
}

BtreeDirectory::~BtreeDirectory()
{
    try
    {
        flush_cache();
    }
    catch (...)
    {
    }
}

void BtreeDirectory::flush_cache()
{
    for (auto&& n : m_node_cache)
    {
        if (n.is_dirty())
        {
            write_node(n.page_number(), n);
            n.clear_dirty();
        }
    }
}

void BtreeDirectory::clear_cache() { m_node_cache.clear(); }

BtreeDirectory::Node* BtreeDirectory::get_node(uint32_t parent_num, uint32_t num)
{
    m_node_cache.emplace_back(parent_num, num);
    return &m_node_cache.back();
}

std::pair<size_t, bool> BtreeDirectory::find_node(const std::string& name,
                                                  std::vector<Node>& node_chain)
{
    throw NotImplementedException(__PRETTY_FUNCTION__);
}

void BtreeDirectory::read_node(uint32_t num, BtreeDirectory::Node& n)
{
    if (num == INVALID_PAGE)
        throw CorruptedDirectoryException();
    byte buffer[BLOCK_SIZE];
    if (m_stream->read(buffer, num * BLOCK_SIZE, BLOCK_SIZE) != BLOCK_SIZE)
        throw CorruptedDirectoryException();
    n.from_buffer(buffer, sizeof(buffer));
}

void BtreeDirectory::write_node(uint32_t num, const BtreeDirectory::Node& n)
{
    if (num == INVALID_PAGE)
        throw CorruptedDirectoryException();
    byte buffer[BLOCK_SIZE];
    n.to_buffer(buffer, sizeof(buffer));
    m_stream->write(buffer, num * BLOCK_SIZE, BLOCK_SIZE);
}

bool BtreeDirectory::get_entry(const std::string& name, id_type& id, int& type)
{
    throw NotImplementedException(__PRETTY_FUNCTION__);
}

bool BtreeDirectory::add_entry(const std::string& name, const id_type& id, int type)
{
    throw NotImplementedException(__PRETTY_FUNCTION__);
}

bool BtreeDirectory::remove_entry(const std::string& name, id_type& id, int& type)
{
    throw NotImplementedException(__PRETTY_FUNCTION__);
}

bool BtreeDirectory::validate_free_list()
{
    auto pg = get_root_page();
    uint32_t prev = INVALID_PAGE;
    FreePage fp;
    for (size_t i = 0; i < get_num_free_page(); ++i)
    {
        read_free_page(pg, fp);
        if (fp.prev != prev)
            return false;
        prev = pg;
        pg = fp.next;
    }
    return pg == INVALID_PAGE;
}
}
