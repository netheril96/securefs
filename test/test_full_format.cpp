#include "btree_dir.h"
#include "full_format.h"
#include "fuse_high_level_ops_base.h"
#include "mystring.h"
#include "platform.h"
#include "tags.h"
#include "test_common.h"

#include <doctest/doctest.h>
#include <fruit/fruit.h>
#include <memory>

namespace securefs::full_format
{
namespace
{
    template <bool CaseInsensitive>
    fruit::Component<FuseHighLevelOpsBase> get_test_component(std::shared_ptr<OSService> os)
    {
        return fruit::createComponent()
            .bind<FuseHighLevelOpsBase, full_format::FuseHighLevelOps>()
            .install(full_format::get_table_io_component, 2)
            .template registerProvider<fruit::Annotated<tVerify, bool>()>([]() { return true; })
            .template registerProvider<fruit::Annotated<tStoreTimeWithinFs, bool>()>(
                []() { return false; })
            .template registerProvider<fruit::Annotated<tReadOnly, bool>()>([]() { return false; })
            .template registerProvider<fruit::Annotated<tCaseInsensitive, bool>()>(
                []() { return CaseInsensitive; })
            .template bind<Directory, BtreeDirectory>()
            .template registerProvider<fruit::Annotated<tMaxPaddingSize, unsigned>()>(
                []() { return 0u; })
            .template registerProvider<fruit::Annotated<tIvSize, unsigned>()>([]() { return 12u; })
            .template registerProvider<fruit::Annotated<tBlockSize, unsigned>()>([]()
                                                                                 { return 60u; })
            .template registerProvider<fruit::Annotated<tMasterKey, key_type>()>(
                []() { return key_type(0x99); })
            .template registerProvider<fruit::Annotated<tEnableXattr, bool>()>([]() { return true; })
            .registerProvider(
                []()
                {
                    return CaseInsensitive ? Directory::DirNameComparison{&case_insensitive_compare}
                                           : Directory::DirNameComparison{&binary_compare};
                })
            .registerProvider([]() { return OwnerOverride{}; })
            .bindInstance(*os);
    }
    TEST_CASE("Full format test (case sensitive)")
    {
        auto temp_dir_name = OSService::temp_name("tmp/full", "dir");
        OSService::get_default().ensure_directory(temp_dir_name, 0755);
        auto root = std::make_shared<OSService>(temp_dir_name);
        fruit::Injector<FuseHighLevelOpsBase> injector(get_test_component<false>, root);
        testing::test_fuse_ops(injector.get<FuseHighLevelOpsBase&>(),
                               *root,
                               testing::CaseSensitivity::CaseSensitive,
                               testing::ResolveSymlinks::YES);
    }
    TEST_CASE("Full format test (case insensitive)")
    {
        auto temp_dir_name = OSService::temp_name("tmp/full", "dir");
        OSService::get_default().ensure_directory(temp_dir_name, 0755);
        auto root = std::make_shared<OSService>(temp_dir_name);
        fruit::Injector<FuseHighLevelOpsBase> injector(get_test_component<true>, root);
        testing::test_fuse_ops(injector.get<FuseHighLevelOpsBase&>(),
                               *root,
                               testing::CaseSensitivity::CaseInsensitive,
                               testing::ResolveSymlinks::YES);
    }
}    // namespace
}    // namespace securefs::full_format
