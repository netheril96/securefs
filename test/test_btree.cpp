#ifdef UNIT_TEST
#include "btree_dir.h"
#include "utils.h"

#include <catch.hpp>
#include <format.h>

#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <unordered_set>
#include <limits>

#include <unistd.h>
#include <fcntl.h>

static void test(securefs::BtreeDirectory& dir,
                 securefs::Directory& reference,
                 unsigned rounds,
                 double prob_get,
                 double prob_add,
                 double prob_del)
{
    bool is_prob_valid = (prob_get >= 0 && prob_add >= 0 && prob_del >= 0
                          && prob_get + prob_add + prob_del <= 1.0);
    REQUIRE(is_prob_valid);

    std::mt19937 engine{0x99fe331};
    std::uniform_real_distribution<> prob_dist(0, 1);
    std::uniform_int_distribution<unsigned> name_dist(0, std::numeric_limits<unsigned>::max());
    std::vector<std::string> filenames, filenames_prime;

    auto inserter = [&](const std::string& name, const securefs::id_type& id, int type) -> bool
    {
        filenames.push_back(name);
        return true;
    };

    auto inserter_prime =
        [&](const std::string& name, const securefs::id_type& id, int type) -> bool
    {
        filenames_prime.push_back(name);
        return true;
    };

    dir.iterate_over_entries(inserter);
    reference.iterate_over_entries(inserter_prime);

    std::sort(filenames.begin(), filenames.end());
    std::sort(filenames_prime.begin(), filenames_prime.end());
    bool equal_filenames = (filenames == filenames_prime);
    REQUIRE(equal_filenames);

    securefs::id_type id, id_prime;
    int type, type_prime;
    for (unsigned i = 0; i < rounds; ++i)
    {
        auto p = prob_dist(engine);
        if (p < prob_get)
        {
            filenames.clear();
            dir.iterate_over_entries(inserter);
            for (const std::string& n : filenames)
            {
                bool got = dir.get_entry(n, id, type);
                bool got_prime = reference.get_entry(n, id_prime, type_prime);
                REQUIRE(got == got_prime);
                REQUIRE(id == id_prime);
                REQUIRE(type == type_prime);
            }
        }
        else if (p < prob_get + prob_add)
        {
            auto name = fmt::format("{:10d}", name_dist(engine));
            securefs::generate_random(id.data(), id.size());
            type = S_IFREG;
            bool added = dir.add_entry(name, id, type);
            bool added_prime = reference.add_entry(name, id, type);
            REQUIRE(added == added_prime);
            filenames.push_back(std::move(name));
        }
        else if (p < prob_get + prob_add + prob_del)
        {
            if (filenames.empty())
                continue;
            std::uniform_int_distribution<size_t> index_dist(0, filenames.size() - 1);
            size_t idx = index_dist(engine);
            bool removed = dir.remove_entry(filenames[idx], id, type);
            bool removed_prime = reference.remove_entry(filenames[idx], id_prime, type_prime);
            REQUIRE(removed == removed_prime);
            filenames.erase(filenames.begin() + idx);
        }
        else
        {
            REQUIRE(dir.validate_free_list());
            REQUIRE_NOTHROW(dir.validate_btree_structure());
        }
    }
}

TEST_CASE("Test BtreeDirectory")
{
    const size_t NUM_ENTRIES = 1000;
    std::vector<std::string> names;
    for (size_t i = 0; i < NUM_ENTRIES; ++i)
    {
        names.emplace_back(fmt::format("file{}.abc", i));
    }
    std::mt19937 engine{std::random_device{}()};
    std::shuffle(names.begin(), names.end(), engine);
    std::vector<securefs::id_type> ids(NUM_ENTRIES);
    for (auto&& d : ids)
        securefs::generate_random(d.data(), d.size());

    securefs::key_type null_key{};
    securefs::id_type null_id{};

    char tmp1[] = "/tmp/securefs.btree1.XXXXXX";
    char tmp2[] = "/tmp/securefs.btree2.XXXXXX";
    char tmp3[] = "/tmp/securefs.btree3.XXXXXX";
    char tmp4[] = "/tmp/securefs.btree4.XXXXXX";

    securefs::BtreeDirectory dir(::mkstemp(tmp1), ::mkstemp(tmp2), null_key, null_id, true);
    securefs::SimpleDirectory ref_dir(::mkstemp(tmp3), ::mkstemp(tmp4), null_key, null_id, true);

    test(dir, ref_dir, 1000, 0.3, 0.5, 0.1);
    test(dir, ref_dir, 1000, 0.3, 0.1, 0.5);
    test(dir, ref_dir, 1000, 0.3, 0.3, 0.3);

    for (size_t i = 0; i < NUM_ENTRIES; ++i)
    {
        REQUIRE(dir.add_entry(names[i], ids[i], securefs::FileBase::REGULAR_FILE));
    }
    REQUIRE_NOTHROW(dir.validate_btree_structure());
    for (size_t i = 0; i < NUM_ENTRIES / 2; ++i)
    {
        int type;
        REQUIRE(dir.remove_entry(names[i], ids[i], type));
    }
    REQUIRE(dir.validate_free_list());
    REQUIRE_NOTHROW(dir.validate_btree_structure());
    for (size_t i = NUM_ENTRIES / 2; i < NUM_ENTRIES; ++i)
    {
        securefs::id_type id;
        int type;
        REQUIRE(dir.get_entry(names[i], id, type));
        REQUIRE(id == ids[i]);
    }
}
#endif
