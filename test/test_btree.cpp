#include "btree_dir.h"
#include "crypto.h"
#include "myutils.h"
#include "test_common.h"

#include <algorithm>
#include <limits>
#include <random>
#include <string>
#include <unordered_set>
#include <vector>

#include <cryptopp/rng.h>
#include <doctest/doctest.h>

static void test(securefs::BtreeDirectory& dir,
                 securefs::Directory& reference,
                 unsigned rounds,
                 double prob_get,
                 double prob_add,
                 double prob_del,
                 unsigned sequence) ABSL_EXCLUSIVE_LOCKS_REQUIRED(dir)
    ABSL_EXCLUSIVE_LOCKS_REQUIRED(reference)
{
    (void)sequence;    // May be used later
    bool is_prob_valid = (prob_get >= 0 && prob_add >= 0 && prob_del >= 0
                          && prob_get + prob_add + prob_del <= 1.0);
    REQUIRE(is_prob_valid);

    std::uniform_real_distribution<> prob_dist(0, 1);
    std::uniform_int_distribution<int> name_dist(0, 65535);
    std::vector<std::string> filenames, filenames_prime;

    securefs::Directory::callback inserter
        = [&](const std::string& name, const securefs::id_type&, int) -> bool
    {
        filenames.push_back(name);
        return true;
    };

    securefs::Directory::callback inserter_prime
        = [&](const std::string& name, const securefs::id_type&, int) -> bool
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
        auto p = prob_dist(get_random_number_engine());
        if (p < prob_get)
        {
            filenames.clear();
            dir.iterate_over_entries(inserter);
            for (const std::string& n : filenames)
            {
                bool got = dir.get_entry(n, id, type);
                bool got_prime = reference.get_entry(n, id_prime, type_prime);
                REQUIRE(got == got_prime);
                bool id_equal = (id == id_prime);
                REQUIRE(id_equal);
                REQUIRE(type == type_prime);
            }
        }
        else if (p < prob_get + prob_add)
        {
            auto name = absl::StrFormat("%12d", name_dist(get_random_number_engine()));
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
            size_t idx = index_dist(get_random_number_engine());
            bool removed = dir.remove_entry(filenames[idx], id, type);
            bool removed_prime = reference.remove_entry(filenames[idx], id_prime, type_prime);
            REQUIRE(removed == removed_prime);
            filenames.erase(filenames.begin() + idx);
        }
        else
        {
            REQUIRE(dir.validate_free_list());
            REQUIRE(dir.validate_btree_structure());
        }
    }
}

static void test_btree_dir(unsigned max_padding_size)
{
    securefs::key_type key(0x3e);
    securefs::id_type null_id{};

    securefs::OSService service("tmp");
    auto tmp1 = service.temp_name("btree", "1");
    auto tmp2 = service.temp_name("btree", "2");
    auto tmp3 = service.temp_name("btree", "3");
    auto tmp4 = service.temp_name("btree", "4");

    int flags = O_RDWR | O_EXCL | O_CREAT;

    {
        securefs::BtreeDirectory dir(service.open_file_stream(tmp1, flags, 0644),
                                     service.open_file_stream(tmp2, flags, 0644),
                                     key,
                                     null_id,
                                     true,
                                     8000,
                                     12,
                                     max_padding_size,
                                     false);
        securefs::SimpleDirectory ref_dir(service.open_file_stream(tmp3, flags, 0644),
                                          service.open_file_stream(tmp4, flags, 0644),
                                          key,
                                          null_id,
                                          true,
                                          8000,
                                          12,
                                          max_padding_size,
                                          false);
        securefs::DoubleFileLockGuard dflg(dir, ref_dir);
        test(dir, ref_dir, 1000, 0.3, 0.5, 0.1, 1);
        test(dir, ref_dir, 1000, 0.3, 0.1, 0.5, 2);
        test(dir, ref_dir, 1000, 0.3, 0.3, 0.3, 3);
        dir.flush();
        ref_dir.flush();
    }
    {
        // Test if the data persists on the disk
        securefs::BtreeDirectory dir(service.open_file_stream(tmp1, O_RDWR, 0),
                                     service.open_file_stream(tmp2, O_RDWR, 0),
                                     key,
                                     null_id,
                                     true,
                                     8000,
                                     12,
                                     max_padding_size,
                                     false);
        securefs::SimpleDirectory ref_dir(service.open_file_stream(tmp3, O_RDWR, 0),
                                          service.open_file_stream(tmp4, O_RDWR, 0),
                                          key,
                                          null_id,
                                          true,
                                          8000,
                                          12,
                                          max_padding_size,
                                          false);
        securefs::DoubleFileLockGuard dflg(dir, ref_dir);
        test(dir, ref_dir, 1000, 0.3, 0.3, 0.3, 4);
        dir.flush();
        ref_dir.flush();
    }
}

TEST_CASE("Test BtreeDirectory")
{
    test_btree_dir(0);
    test_btree_dir(128);
}
