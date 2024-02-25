#pragma once
#include "files.h"
#include "myutils.h"

#include <memory>
#include <stdio.h>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <absl/container/flat_hash_map.h>

namespace securefs
{
const uint32_t INVALID_PAGE = -1;
const int BTREE_MAX_DEPTH = 32;
const int BTREE_MAX_NUM_ENTRIES = 13;

static_assert(BTREE_MAX_NUM_ENTRIES * (Directory::MAX_FILENAME_LENGTH + 1 + ID_LENGTH + 4)
                      + (BTREE_MAX_NUM_ENTRIES + 1) * 4 + 4 + 4
                  <= BLOCK_SIZE,
              "A btree node may not fit in a single block");

class CorruptedDirectoryException : public VerificationException
{
public:
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
    BtreeNode(BtreeNode&& other) noexcept
        : m_parent_num(other.m_parent_num)
        , m_num(other.m_num)
        , m_child_indices(std::move(other.m_child_indices))
        , m_entries(std::move(other.m_entries))
        , m_dirty(false)
    {
        std::swap(m_dirty, other.m_dirty);
        other.m_num = INVALID_PAGE;
    }

    BtreeNode& operator=(BtreeNode&& other) noexcept
    {
        if (this == &other)
            return *this;
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
    bool from_buffer(const byte* buffer, size_t size);
    void to_buffer(byte* buffer, size_t size) const;
};

class BtreeDirectory final : public Directory
{
private:
    typedef BtreeNode Node;
    typedef DirEntry Entry;
    class FreePage;

private:
    absl::flat_hash_map<uint32_t, std::unique_ptr<Node>> m_node_cache;

private:
    bool read_node(uint32_t, Node&) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void read_free_page(uint32_t, FreePage&) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void write_node(uint32_t, const Node&) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void write_free_page(uint32_t, const FreePage&) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void deallocate_page(uint32_t) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    uint32_t allocate_page() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    Node* retrieve_node(uint32_t parent_num, uint32_t num) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    Node* retrieve_existing_node(uint32_t num) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void del_node(Node*) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    Node* get_root_node() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void flush_cache() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void clear_cache() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void adjust_children_in_cache(BtreeNode* n, uint32_t parent)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void adjust_children_in_cache(BtreeNode* n) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this)
    {
        adjust_children_in_cache(n, n->page_number());
    }
    void rotate(BtreeNode* left, BtreeNode* right, Entry& separator)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void merge(BtreeNode* left, BtreeNode* right, BtreeNode* parent, ptrdiff_t entry_index)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    std::tuple<Node*, ptrdiff_t, bool> find_node(const std::string& name)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    std::pair<ptrdiff_t, BtreeNode*> find_sibling(const BtreeNode* parent, const BtreeNode* child)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    void insert_and_balance(Node*, Entry, uint32_t additional_child, int depth)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    Node* replace_with_sub_entry(Node*, ptrdiff_t index, int depth)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void balance_up(Node*, int depth) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    bool validate_node(const Node* n, int depth) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void write_dot_graph(const Node*, FILE*) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    template <class Callback>
    void recursive_iterate(const Node* n, const Callback& cb, int depth)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    template <class Callback>
    void mutable_recursive_iterate(Node* n, const Callback& cb, int depth)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

protected:
    void subflush() override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

public:
    template <class... Args>
    explicit BtreeDirectory(Args&&... args) : Directory(std::forward<Args>(args)...)
    {
    }
    ~BtreeDirectory() override;

protected:
    bool get_entry_impl(const std::string& name, id_type& id, int& type) override
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    bool add_entry_impl(const std::string& name, const id_type& id, int type) override
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    bool remove_entry_impl(const std::string& name, id_type& id, int& type) override
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void iterate_over_entries_impl(const callback&) override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

public:
    virtual bool empty() override ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void rebuild() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

public:
    bool validate_free_list() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    bool validate_btree_structure() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void to_dot_graph(const char* filename) ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
};

template <class... Args>
inline std::unique_ptr<FileBase> btree_make_file_from_type(int type, Args&&... args)
{
    switch (type)
    {
    case FileBase::REGULAR_FILE:
        return securefs::make_unique<RegularFile>(std::forward<Args>(args)...);
    case FileBase::SYMLINK:
        return securefs::make_unique<Symlink>(std::forward<Args>(args)...);
    case FileBase::DIRECTORY:
        return securefs::make_unique<BtreeDirectory>(std::forward<Args>(args)...);
    case FileBase::BASE:
        return securefs::make_unique<FileBase>(std::forward<Args>(args)...);
    default:
        break;
    }
    throwInvalidArgumentException("Unrecognized file type");
}
}    // namespace securefs
