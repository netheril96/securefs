#pragma once
#include "files.h"

#include <vector>
#include <utility>
#include <memory>
#include <string>
#include <unordered_map>
#include <tuple>
#include <stdio.h>

namespace securefs
{
const uint32_t INVALID_PAGE = -1;
const int BTREE_MAX_DEPTH = 32;
const int MAX_NUM_ENTRIES = 13;

static_assert(MAX_NUM_ENTRIES * (Directory::MAX_FILENAME_LENGTH + 1 + ID_LENGTH + 4)
                      + (MAX_NUM_ENTRIES + 1) * 4
                      + 4 + 4
                  <= BLOCK_SIZE,
              "A btree node may not fit in a single block");

class CorruptedDirectoryException : public SeriousException
{
public:
    const char* type_name() const noexcept override { return "CorruptedDirectoryException"; }
    std::string message() const override { return "Directory corrupted"; }
};

class DirEntry
{
public:
    std::string filename;
    id_type id;
    uint32_t type;

    int compare(const DirEntry& other) const { return filename.compare(other.filename); }
    int compare(const std::string& name) const { return filename.compare(name); }
    bool operator<(const DirEntry& other) const { return compare(other) < 0; }
    bool operator==(const DirEntry& other) const { return compare(other) == 0; }
    bool operator<(const std::string& other) const { return compare(other) < 0; }
    bool operator==(const std::string& other) const { return compare(other) == 0; }
};

class BtreeNode
{
private:
    uint32_t m_parent_num, m_num;
    std::vector<uint32_t> m_child_indices;
    std::vector<DirEntry> m_entries;
    bool m_dirty;

public:
    explicit BtreeNode(uint32_t parent, uint32_t num)
        : m_parent_num(parent), m_num(num), m_dirty(false)
    {
    }
    BtreeNode(BtreeNode&& other) noexcept : m_parent_num(other.m_parent_num),
                                            m_num(other.m_num),
                                            m_child_indices(std::move(other.m_child_indices)),
                                            m_entries(std::move(other.m_entries))
    {
        std::swap(m_dirty, other.m_dirty);
        other.m_num = INVALID_PAGE;
    }

    BtreeNode& operator=(BtreeNode&& other) noexcept
    {
        if (this == &other)
            return other;
        std::swap(m_child_indices, other.m_child_indices);
        std::swap(m_entries, other.m_entries);
        std::swap(m_dirty, other.m_dirty);
        std::swap(m_num, other.m_num);
        std::swap(m_parent_num, other.m_parent_num);
        return *this;
    }

    uint32_t page_number() const { return m_num; }
    uint32_t parent_page_number() const { return m_parent_num; }
    uint32_t& mutable_parent_page_number()
    {
        m_dirty = true;
        return m_parent_num;
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

    const std::vector<DirEntry>& entries() const noexcept { return m_entries; }
    const std::vector<uint32_t>& children() const noexcept { return m_child_indices; }
    std::vector<DirEntry>& mutable_entries() noexcept
    {
        m_dirty = true;
        return m_entries;
    }
    std::vector<uint32_t>& mutable_children() noexcept
    {
        m_dirty = true;
        return m_child_indices;
    }
    void from_buffer(const byte* buffer, size_t size);
    void to_buffer(byte* buffer, size_t size) const;
};

class BtreeDirectory : public Directory
{
private:
    typedef BtreeNode Node;
    typedef DirEntry Entry;
    class FreePage;

private:
    std::unordered_map<uint32_t, std::unique_ptr<Node>> m_node_cache;

private:
    void read_node(uint32_t, Node&);
    void read_free_page(uint32_t, FreePage&);
    void write_node(uint32_t, const Node&);
    void write_free_page(uint32_t, const FreePage&);
    void deallocate_page(uint32_t);
    uint32_t allocate_page();

    Node* get_node(uint32_t parent_num, uint32_t num);
    void eject_node(uint32_t);
    void del_node(Node*);
    Node* get_root_node();
    void flush_cache();
    void clear_cache();

    std::tuple<Node*, ptrdiff_t, bool> find_node(const std::string& name);

    void insert_and_balance(Node*, Entry, uint32_t additional_child, int depth);
    Node* rotate_down(Node*, const Entry&, int depth);
    void merge_up(Node*, int depth);

    void validate_node(const Node* n, int depth);

    void write_dot_graph(const Node*, FILE*);

protected:
    void subflush() override;

public:
    template <class... Args>
    explicit BtreeDirectory(Args&&... args)
        : Directory(std::forward<Args>(args)...)
    {
    }
    ~BtreeDirectory();
    virtual bool get_entry(const std::string& name, id_type& id, int& type) override;
    virtual bool add_entry(const std::string& name, const id_type& id, int type) override;
    virtual bool remove_entry(const std::string& name, id_type& id, int& type) override;
    virtual void iterate_over_entries(callback cb) override
    {
        throw NotImplementedException(__PRETTY_FUNCTION__);
    }
    virtual bool empty() const override { throw NotImplementedException(__PRETTY_FUNCTION__); }
    bool validate_free_list();
    void validate_btree_structure();
    void to_dot_graph(const char* filename);
};
}
