#include "btree_dir.h"

#include <vector>
#include <algorithm>
#include <utility>
#include <type_traits>

namespace
{
const uint32_t INVALID_PAGE = -1;
const int MAX_DEPTH = 32;
const int MAX_NUM_ENTRIES = 13;
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

class BtreeDirectory::FreePage
{
public:
    uint32_t next;
};

void BtreeDirectory::read_free_page(uint32_t num, FreePage& fp)
{
    byte buffer[BLOCK_SIZE];
    if (m_stream->read(buffer, num * BLOCK_SIZE, BLOCK_SIZE) != BLOCK_SIZE)
        throw CorruptedDirectoryException();
    if (from_little_endian<uint32_t>(buffer) != 0)
        throw CorruptedDirectoryException();
    fp.next = from_little_endian<uint32_t>(buffer + sizeof(uint32_t));
}

uint32_t BtreeDirectory::allocate_page()
{
    auto pg = get_start_free_page();
    if (pg == INVALID_PAGE)
    {
        return static_cast<uint32_t>(m_stream->size() / BLOCK_SIZE);
    }
    set_num_free_page(get_num_free_page() - 1);
    return pg;
}

void BtreeDirectory::free_page(uint32_t num)
{
    byte buffer[BLOCK_SIZE] = {};
    to_little_endian(get_start_free_page(), buffer + sizeof(uint32_t));
    m_stream->write(buffer, num * BLOCK_SIZE, BLOCK_SIZE);
    set_start_free_page(num);
    set_num_free_page(get_num_free_page() + 1);
}

class BtreeDirectory::Entry
{
public:
    std::array<char, BtreeDirectory::MAX_FILENAME_LENGTH + 1> filename;
    id_type id;
    uint32_t type;

    int compare(const Entry& other) const { return strcmp(filename.data(), other.filename.data()); }
    int compare(const std::string& name) const { return strcmp(filename.data(), name.c_str()); }
    bool operator<(const Entry& other) const { return compare(other) < 0; }
    bool operator==(const Entry& other) const { return compare(other) == 0; }
    bool operator<(const std::string& other) const { return compare(other) < 0; }
    bool operator==(const std::string& other) const { return compare(other) == 0; }
};

class BtreeDirectory::Node
{
private:
    static_assert(std::is_trivially_copyable<BtreeDirectory::Entry>::value, "");
    static_assert(sizeof(BtreeDirectory::Entry) == 292, "");
    static_assert(8 + 4 * (MAX_NUM_ENTRIES + 1) + sizeof(BtreeDirectory::Entry) * MAX_NUM_ENTRIES
                      <= BLOCK_SIZE,
                  "");

private:
    uint32_t m_num;
    std::vector<uint32_t> m_child_indices;
    std::vector<Entry> m_entries;
    bool m_dirty;

public:
    explicit Node(uint32_t num) : m_num(num), m_dirty(false) {}
    explicit Node(uint32_t num, const Entry& e, uint32_t lchild, uint32_t rchild) : Node(num)
    {
        m_entries.push_back(e);
        m_child_indices.push_back(lchild);
        m_child_indices.push_back(rchild);
    }
    Node(Node&& other) noexcept : m_num(other.m_num),
                                  m_child_indices(std::move(other.m_child_indices)),
                                  m_entries(std::move(other.m_entries))
    {
        std::swap(m_dirty, other.m_dirty);
        other.m_num = INVALID_PAGE;
    }

    Node& operator=(Node&& other) noexcept
    {
        if (this == &other)
            return other;
        std::swap(m_child_indices, other.m_child_indices);
        std::swap(m_entries, other.m_entries);
        std::swap(m_dirty, other.m_dirty);
        std::swap(m_num, other.m_num);
        return *this;
    }

    uint32_t page_number() const { return m_num; }

    size_t num_children() const { return m_child_indices.size(); }
    size_t num_entries() const { return m_entries.size(); }

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
            m_child_indices.push_back(
                read_little_endian_and_forward<uint32_t>(&buffer, end_of_buffer));
        }
        Entry e;
        for (uint16_t i = 0; i < entry_num; ++i)
        {
            buffer = read_and_forward(buffer, end_of_buffer, e.filename);
            buffer = read_and_forward(buffer, end_of_buffer, e.id);
            buffer = read_and_forward(buffer, end_of_buffer, e.type);
            e.filename.back() = 0;    // In case it is not null terminated.
            m_entries.push_back(e);
        }
    }

    void to_buffer(byte* buffer, size_t size) const
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

    bool is_leaf() const
    {
        if (m_child_indices.empty())
            return true;
        if (m_child_indices.size() == m_entries.size() + 1)
            return false;
        throw CorruptedDirectoryException();
    }

    bool is_dirty() const { return m_dirty; }
    void clear_dirty() { m_dirty = false; }

    uint32_t get_child_index(size_t num) const { return m_child_indices.at(num); }
    const Entry& get_entry(size_t num) const { return m_entries.at(num); }

    /*
     * Add an entry to a leaf node
     */
    void add(const Entry& e)
    {
        if (!is_leaf())
            throw InvalidArgumentException(
                "Only leaf nodes can have additonal entry but no additional child");
        m_entries.insert(std::lower_bound(m_entries.begin(), m_entries.end(), e), e);
        m_dirty = true;
    }

    /*
     * Add an entry to a non-leaf node
     * @child index of the newly splitted child
     */
    void add(uint32_t child, const Entry& e)
    {
        if (is_leaf())
            throw InvalidArgumentException("Cannot add children to a leaf node");
        auto iter = std::lower_bound(m_entries.begin(), m_entries.end(), e);
        auto iter_index = iter - m_entries.begin();
        m_entries.insert(iter, e);
        m_child_indices.insert(m_child_indices.begin() + iter_index + 1, child);
        m_dirty = true;
    }

    Entry split(Node& other_part)
    {
        if (m_entries.size() < 3 || m_entries.size() % 2 != 1)
            throw InvalidArgumentException("Not fit for node splitting");
        other_part.m_entries.clear();
        other_part.m_child_indices.clear();
        other_part.m_dirty = true;

        auto middle_index = m_entries.size() / 2;
        Entry e = other_part.m_entries[middle_index];
        auto start = m_entries.begin() + middle_index + 1;
        other_part.m_entries.assign(start, m_entries.end());
        m_entries.erase(start, m_entries.end());
        if (!is_leaf())
        {
            auto start = m_child_indices.begin() + middle_index + 1;
            other_part.m_child_indices.assign(start, m_child_indices.end());
            m_child_indices.erase(start, m_child_indices.end());
        }
        m_dirty = true;
        return e;
    }

    void merge(const Node& other_part, const Entry& e)
    {
        m_entries.push_back(e);
        m_entries.insert(m_entries.end(), other_part.m_entries.begin(), other_part.m_entries.end());
        m_child_indices.insert(m_child_indices.end(),
                               other_part.m_child_indices.begin(),
                               other_part.m_child_indices.end());
        m_dirty = true;
    }

    std::pair<size_t, bool> find(const std::string& name)
    {
        auto iter = std::lower_bound(m_entries.begin(), m_entries.end(), name);
        if (iter != m_entries.end() && name == iter->filename.data())
            return std::make_pair(iter - m_entries.begin(), true);
        return std::make_pair(iter - m_entries.begin(), false);
    }
};

std::pair<size_t, bool> BtreeDirectory::find_node(const std::string& name,
                                                  std::vector<Node>& node_chain)
{
    try
    {
        node_chain.clear();
        auto current_page = get_root_page();
        node_chain.emplace_back(current_page);
        read_node(current_page, node_chain.back());
        for (int i = 0; i < MAX_DEPTH; ++i)
        {
            auto find_result = node_chain.back().find(name);
            if (find_result.second || node_chain.back().is_leaf())
                return find_result;
            auto child = node_chain.back().get_child_index(find_result.first);
            node_chain.emplace_back(child);
            read_node(child, node_chain.back());
        }
        throw CorruptedDirectoryException();
        // The B-tree structure contains a loop and is therefore invalid
    }
    catch (const std::out_of_range&)
    {
        throw CorruptedDirectoryException();
    }
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
    if (get_root_page() == INVALID_PAGE)
        return false;
    std::vector<Node> node_chain;
    auto find_result = find_node(name, node_chain);
    if (find_result.second)
    {
        const Entry& e = node_chain.back().get_entry(find_result.first);
        id = e.id;
        type = e.type;
    }
    return find_result.second;
}

bool BtreeDirectory::add_entry(const std::string& name, const id_type& id, int type)
{
    if (name.size() > MAX_FILENAME_LENGTH)
        throw OSException(ENAMETOOLONG);
    if (get_root_page() == INVALID_PAGE)
        return false;
    std::vector<Node> node_chain;
    auto find_result = find_node(name, node_chain);
    if (find_result.second)
        return false;
    Entry e;
    std::copy(name.begin(), name.end(), e.filename.begin());
    std::fill(e.filename.begin() + name.size(), e.filename.end(), 0);
    e.id = id;
    e.type = type;
    node_chain.back().add(e);
    for (size_t i = node_chain.size(); i-- > 0;)
    {
        auto&& node = node_chain[i];
        if (node.num_entries() > MAX_NUM_ENTRIES)
        {
            Node sibling(allocate_page());
            Entry e = node.split(sibling);
            if (i > 0)
            {
                node_chain[i - 1].add(sibling.page_number(), e);
            }
            else
            {
                Node root(allocate_page(), e, node.page_number(), sibling.page_number());
                write_node(root.page_number(), root);
                set_root_page(root.page_number());
            }
            write_node(sibling.page_number(), sibling);
        }
        else
            break;
    }
    for (auto&& n : node_chain)
    {
        if (n.is_dirty())
            write_node(n.page_number(), n);
    }
    return true;
}
}
