#pragma once
#include "files.h"

#include <vector>
#include <utility>

namespace securefs
{
class BtreeDirectory : public Directory
{
private:
    class Node;
    class FreePage;
    class Entry;

private:
    void read_node(uint32_t, Node&);
    void read_free_page(uint32_t, FreePage&);
    void write_node(uint32_t, const Node&);
    void write_free_page(uint32_t, const FreePage&);
    void deallocate_page(uint32_t);
    uint32_t allocate_page();
    std::pair<size_t, bool> find_node(const std::string& name, std::vector<Node>& node_chain);

public:
    template <class... Args>
    explicit BtreeDirectory(Args&&... args)
        : Directory(std::forward<Args>(args)...)
    {
    }
    virtual bool get_entry(const std::string& name, id_type& id, int& type) override;
    virtual bool add_entry(const std::string& name, const id_type& id, int type) override;
    virtual bool remove_entry(const std::string& name, id_type& id, int& type) override;
    virtual void iterate_over_entries(callback cb) override
    {
        throw NotImplementedException(__PRETTY_FUNCTION__);
    }
    virtual bool empty() const override { throw NotImplementedException(__PRETTY_FUNCTION__); }
    bool validate_free_list();
};
}
