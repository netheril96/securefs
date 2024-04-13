#include "test_common.h"
#include "crypto.h"
#include "fuse_high_level_ops_base.h"
#include "lite_format.h"
#include "lite_long_name_lookup_table.h"
#include "logger.h"
#include "myutils.h"

#include <cryptopp/osrng.h>

#include <cstddef>
#include <cstdlib>
#include <fuse/fuse.h>
#include <string>
#include <thread>
#include <vector>

std::mt19937& get_random_number_engine()
{
    struct Initializer
    {
        std::mt19937 mt;

        Initializer()
        {
            uint32_t data[64];
            const char* seed = std::getenv("SECUREFS_TEST_SEED");
            if (seed && seed[0])
            {
                securefs::parse_hex(seed, reinterpret_cast<unsigned char*>(data), sizeof(data));
            }
            else
            {
                CryptoPP::OS_GenerateRandomBlock(
                    false, reinterpret_cast<unsigned char*>(data), sizeof(data));
            }
            INFO_LOG("Random seed: %s",
                     securefs::hexify(reinterpret_cast<const unsigned char*>(data), sizeof(data))
                         .c_str());
            std::seed_seq seq(std::begin(data), std::end(data));
            mt.seed(seq);
        }
    };

    static thread_local Initializer initializer;
    return initializer.mt;
}

namespace securefs::testing
{
namespace
{
    constexpr std::string_view kLongFileNameExample1
        = u8"✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅"
          u8"✅"
          "✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅";
    static_assert(kLongFileNameExample1.size() > 240 && kLongFileNameExample1.size() < 255);

    constexpr std::string_view kLongFileNameExample2 = u8"🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️";
    static_assert(kLongFileNameExample2.size() > 240 && kLongFileNameExample2.size() < 255);

    using ListDirResult = std::vector<std::pair<std::string, fuse_stat>>;
    ListDirResult listdir(FuseHighLevelOpsBase& op, const char* path)
    {
        ListDirResult result;
        fuse_file_info info{};
        REQUIRE(op.vopendir(path, &info, nullptr) == 0);
        DEFER(op.vreleasedir(path, &info, nullptr));
        REQUIRE(op.vreaddir(
                    path,
                    &result,
                    [](void* buf, const char* name, const fuse_stat* st, fuse_off_t off)
                    {
                        static_cast<ListDirResult*>(buf)->emplace_back(name,
                                                                       st ? *st : fuse_stat{});
                        return 0;
                    },
                    0,
                    &info,
                    nullptr)
                == 0);
        std::sort(result.begin(),
                  result.end(),
                  [](const auto& p1, const auto& p2) { return p1.first < p2.first; });
        return result;
    }
    std::vector<std::string> names(const ListDirResult& l)
    {
        std::vector<std::string> result;
        std::transform(l.begin(),
                       l.end(),
                       std::back_inserter(result),
                       [](const auto& pair) { return pair.first; });
        return result;
    }
    std::string getpath(FuseHighLevelOpsBase& ops, const char* path)
    {
        std::string result(strlen(path) * 2, 0);
        REQUIRE(ops.vgetpath(path, result.data(), result.size() + 1, nullptr, nullptr) == 0);
        result.resize(strlen(result.c_str()));
        return result;
    }
    std::vector<std::string> listxattr(FuseHighLevelOpsBase& ops, const char* path)
    {
        auto size = ops.vlistxattr(path, nullptr, 0, nullptr);
        if (size <= 0)
        {
            return {};
        }
        std::vector<char> buffer(size);
        REQUIRE(ops.vlistxattr(path, buffer.data(), buffer.size(), nullptr) > 0);
        std::vector<std::string> result;
        for (const char* ptr = buffer.data(); ptr < buffer.data() + buffer.size();
             ptr += result.back().size() + 1)
        {
            result.emplace_back(ptr);
        }
        std::sort(result.begin(), result.end());
        return result;
    }
    std::string getxattr(FuseHighLevelOpsBase& ops, const char* path, const char* name)
    {
        auto size = ops.vgetxattr(path, name, nullptr, 0, 0, nullptr);
        REQUIRE(size > 0);
        std::string result(size, '\0');
        REQUIRE(ops.vgetxattr(path, name, result.data(), result.size(), 0, nullptr) > 0);
        return result;
    }
}    // namespace
void test_fuse_ops(FuseHighLevelOpsBase& ops, OSService& repo_root, bool case_insensitive)
{
    CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", ".."});

    fuse_context ctx{};
    ctx.uid = 2;
    ctx.gid = 3;

    {
        fuse_file_info info{};
        REQUIRE(ops.vcreate("/hello", 0644, &info, &ctx) == 0);
        REQUIRE(ops.vrelease(nullptr, &info, &ctx) == 0);

        fuse_stat st{};
        REQUIRE(ops.vgetattr("/hello", &st, &ctx) == 0);
        CHECK((st.st_mode & S_IFMT) == S_IFREG);
        CHECK(st.st_size == 0);

        if (case_insensitive)
        {
            CHECK(getpath(ops, "/HeLLo") == "/hello");
        }
    }

    CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", "..", "hello"});

    {
        fuse_file_info info{};
        REQUIRE(ops.vcreate(absl::StrCat("/", kLongFileNameExample1).c_str(), 0644, &info, &ctx)
                == 0);
        REQUIRE(ops.vrelease(nullptr, &info, &ctx) == 0);
        CHECK(names(listdir(ops, "/"))
              == std::vector<std::string>{".", "..", "hello", std::string(kLongFileNameExample1)});
    }

    {
        // Asserts read and write

        std::vector<char> written(333), read(444);
        generate_random(written.data(), written.size());
        fuse_file_info write_info{};
        write_info.flags = O_WRONLY;
        REQUIRE(ops.vopen(absl::StrCat("/", kLongFileNameExample1).c_str(), &write_info, &ctx)
                == 0);
        REQUIRE(ops.vwrite(nullptr, written.data(), written.size(), 1, &write_info, &ctx)
                == written.size());

        fuse_stat st{};
        CHECK(ops.vfgetattr(nullptr, &st, &write_info, &ctx) == 0);
        CHECK(st.st_size == written.size() + 1);

        std::thread concurrent_read_thread(
            [&]()
            {
                fuse_file_info read_info{};
                read_info.flags = O_RDONLY;
                REQUIRE(
                    ops.vopen(absl::StrCat("/", kLongFileNameExample1).c_str(), &read_info, &ctx)
                    == 0);
                REQUIRE(ops.vread(nullptr, read.data(), read.size(), 0, &read_info, &ctx)
                        == written.size() + 1);
                REQUIRE(ops.vrelease(nullptr, &read_info, &ctx) == 0);
                CHECK(read.front() == 0);
                CHECK(std::string_view(written.data(), written.size())
                      == std::string_view(read.data() + 1, written.size()));
            });
        concurrent_read_thread.join();

        REQUIRE(ops.vrelease(nullptr, &write_info, &ctx) == 0);
    }

    CHECK(ops.vunlink("/hello", &ctx) == 0);
    CHECK(ops.vunlink(absl::StrCat("/", kLongFileNameExample1).c_str(), &ctx) == 0);
    CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", ".."});

    // Lite format specific test case
    if (dynamic_cast<lite_format::FuseHighLevelOps*>(&ops))
    {
        LongNameLookupTable root_long_name_table(
            repo_root.norm_path_narrowed(lite_format::kLongNameTableFileName), true);
        LockGuard<LongNameLookupTable> lg(root_long_name_table);
        CHECK(root_long_name_table.list_hashes() == std::vector<std::string>{});
    }

    REQUIRE(ops.vmkdir("/cbd", 0755, &ctx) == 0);
    REQUIRE(ops.vmkdir("/aBc", 0755, &ctx) == 0);
    REQUIRE(ops.vmkdir("/aBc/yyyyY", 0755, &ctx) == 0);
    if (case_insensitive)
    {
        CHECK(getpath(ops, "/ABC/YYYYY") == "/aBc/yyyyY");
    }
    CHECK(names(listdir(ops, "/")) == std::vector<std::string>{".", "..", "aBc", "cbd"});

    REQUIRE(ops.vrename("/aBc", absl::StrCat("/cbd/", kLongFileNameExample2).c_str(), &ctx) == 0);
    {
        fuse_stat st{};
        REQUIRE(ops.vgetattr("/abc", &st, &ctx) == -ENOENT);
        REQUIRE(ops.vgetattr(absl::StrCat("/cbd/", kLongFileNameExample2).c_str(), &st, &ctx) == 0);
        CHECK((st.st_mode & S_IFMT) == S_IFDIR);
        CHECK(names(listdir(ops, "/cbd"))
              == std::vector<std::string>{".", "..", std::string(kLongFileNameExample2)});
    }
    {
        REQUIRE(ops.vrename(absl::StrCat("/cbd/", kLongFileNameExample2).c_str(),
                            absl::StrCat("/cbd/", kLongFileNameExample1).c_str(),
                            &ctx)
                == 0);
        CHECK(names(listdir(ops, "/cbd"))
              == std::vector<std::string>{".", "..", std::string(kLongFileNameExample1)});
    }
    {
        REQUIRE(ops.vrename(absl::StrCat("/cbd/", kLongFileNameExample1).c_str(), "/000", &ctx)
                == 0);
        REQUIRE(ops.vrename("/000", absl::StrCat("/cbd/", kLongFileNameExample2).c_str(), &ctx)
                == 0);
    }

    if (!is_windows())
    {
        auto symlink_location = absl::StrCat("/cbd/", kLongFileNameExample2, "/", "sym");
        constexpr const char* symlink_target
            = "/888888888888888888888888888888/9999999999999999999/66666666666666666";
        REQUIRE(ops.vsymlink(symlink_target, symlink_location.c_str(), &ctx) == 0);

        fuse_stat st{};
        REQUIRE(ops.vgetattr(symlink_location.c_str(), &st, &ctx) == 0);
        CHECK((st.st_mode & S_IFMT) == S_IFLNK);
        CHECK(st.st_size == strlen(symlink_target));

        std::string read_symlink_target(st.st_size, '\0');
        REQUIRE(ops.vreadlink(symlink_location.c_str(),
                              read_symlink_target.data(),
                              read_symlink_target.size() + 1,
                              &ctx)
                == 0);
        CHECK(read_symlink_target == symlink_target);
    }

    if (!is_windows())
    {
        auto link_target = absl::StrCat("/cbd/", kLongFileNameExample2, "/", kLongFileNameExample1);
        fuse_file_info info{};
        REQUIRE(ops.vcreate(link_target.c_str(), 0644, &info, &ctx) == 0);
        REQUIRE(ops.vlink(link_target.c_str(), "/check-mark", &ctx) == 0);
        fuse_stat st{};
        REQUIRE(ops.vfgetattr(nullptr, &st, &info, &ctx) == 0);
        CHECK(st.st_nlink == 2);
        CHECK(ops.vrelease(nullptr, &info, &ctx) == 0);
        CHECK(ops.vunlink(link_target.c_str(), &ctx) == 0);
        REQUIRE(ops.vgetattr("/check-mark", &st, &ctx) == 0);
        CHECK(st.st_nlink == 1);
    }

    if (!is_windows())
    {
        CHECK(ops.vchmod("/check-mark", 0600, &ctx) == 0);
        fuse_stat st{};
        CHECK(ops.vgetattr("/check-mark", &st, &ctx) == 0);
        CHECK(st.st_mode == 0100600);
    }

    if (is_apple())
    {
        CHECK(listxattr(ops, "/cbd") == std::vector<std::string>{});
        CHECK(ops.vsetxattr("/cbd", "com.apple.FinderInfo", "65535", 5, 0, 0, nullptr) >= 0);
        CHECK(ops.vsetxattr("/cbd", "org.securefs.test", "blah", 4, 0, 0, nullptr) >= 0);
        CHECK(listxattr(ops, "/cbd")
              == std::vector<std::string>{"com.apple.FinderInfo", "org.securefs.test"});
        CHECK(ops.vremovexattr("/cbd", "com.apple.FinderInfo", nullptr) == 0);
        CHECK(listxattr(ops, "/cbd") == std::vector<std::string>{"org.securefs.test"});
        CHECK(getxattr(ops, "/cbd", "org.securefs.test") == "blah");
    }
}
}    // namespace securefs::testing
