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
#include <uni_algo/all.h>

namespace securefs
{
namespace
{
    std::string random_unicode_string(size_t length)
    {
        std::vector<char32_t> buffer;
        buffer.reserve(length);
        auto&& mt = get_random_number_engine();
        std::uniform_int_distribution<uint32_t> dist(1, 0x10FFFF);
        while (buffer.size() < length)
        {
            char32_t value = dist(mt);
            if (una::codepoint::prop(value).Graphic())
            {
                buffer.push_back(value);
            }
        }
        return una::utf32to8({buffer.data(), buffer.size()});
    }

    void test(BtreeDirectory& dir,
              Directory& reference,
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
        std::uniform_int_distribution<int> name_size_dist(0, 60);
        std::vector<std::string> filenames, filenames_prime;

        auto inserter
            = [&](const std::string& name, const id_type&, int) { filenames.push_back(name); };

        auto inserter_prime = [&](const std::string& name, const id_type&, int)
        { filenames_prime.push_back(name); };

        dir.iterate_over_entries(inserter);
        reference.iterate_over_entries(inserter_prime);

        std::sort(filenames.begin(), filenames.end());
        std::sort(filenames_prime.begin(), filenames_prime.end());
        bool equal_filenames = (filenames == filenames_prime);
        REQUIRE(equal_filenames);

        id_type id, id_prime;
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
                    auto got = dir.get_entry(n, id, type);
                    auto got_prime = reference.get_entry(n, id_prime, type_prime);
                    REQUIRE(got == got_prime);
                    bool id_equal = (id == id_prime);
                    REQUIRE(id_equal);
                    REQUIRE(type == type_prime);
                }
            }
            else if (p < prob_get + prob_add)
            {
                auto name = random_unicode_string(name_size_dist(get_random_number_engine()));
                generate_random(id.data(), id.size());
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

    void test_btree_dir(unsigned max_padding_size, Directory::DirNameComparison cmp)
    {
        key_type key(0x3e);
        id_type null_id{};

        OSService service("tmp");
        auto tmp1 = service.temp_name("btree", "1");
        auto tmp2 = service.temp_name("btree", "2");
        auto tmp3 = service.temp_name("btree", "3");
        auto tmp4 = service.temp_name("btree", "4");

        int flags = O_RDWR | O_EXCL | O_CREAT;

#ifdef NDEBUG
        unsigned rounds = 333;
#else
        unsigned rounds = 50;
#endif

        {
            BtreeDirectory dir(cmp,
                               service.open_file_stream(tmp1, flags, 0644),
                               service.open_file_stream(tmp2, flags, 0644),
                               key,
                               null_id,
                               true,
                               8000,
                               12,
                               max_padding_size,
                               false);
            SimpleDirectory ref_dir(cmp,
                                    service.open_file_stream(tmp3, flags, 0644),
                                    service.open_file_stream(tmp4, flags, 0644),
                                    key,
                                    null_id,
                                    true,
                                    8000,
                                    12,
                                    max_padding_size,
                                    false);
            DoubleFileLockGuard dflg(dir, ref_dir);
            test(dir, ref_dir, rounds, 0.3, 0.5, 0.1, 1);
            test(dir, ref_dir, rounds, 0.3, 0.1, 0.5, 2);
            test(dir, ref_dir, rounds, 0.3, 0.3, 0.3, 3);
            dir.flush();
            ref_dir.flush();
        }
        {
            // Test if the data persists on the disk
            BtreeDirectory dir(cmp,
                               service.open_file_stream(tmp1, O_RDWR, 0),
                               service.open_file_stream(tmp2, O_RDWR, 0),
                               key,
                               null_id,
                               true,
                               8000,
                               12,
                               max_padding_size,
                               false);
            SimpleDirectory ref_dir(cmp,
                                    service.open_file_stream(tmp3, O_RDWR, 0),
                                    service.open_file_stream(tmp4, O_RDWR, 0),
                                    key,
                                    null_id,
                                    true,
                                    8000,
                                    12,
                                    max_padding_size,
                                    false);
            DoubleFileLockGuard dflg(dir, ref_dir);
            test(dir, ref_dir, rounds, 0.3, 0.3, 0.3, 4);
            dir.flush();
            ref_dir.flush();
        }
    }

    TEST_CASE("Test BtreeDirectory")
    {
        for (unsigned padding : {0, 129})
        {
            test_btree_dir(padding, {binary_compare});
            test_btree_dir(padding, {case_insensitive_compare});
            test_btree_dir(padding, {uni_norm_insensitive_compare});
            test_btree_dir(padding, {case_uni_norm_insensitve_compare});
        }
    }

}    // namespace
}    // namespace securefs
