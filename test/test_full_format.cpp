#include "btree_dir.h"
#include "full_format.h"
#include "fuse_high_level_ops_base.h"
#include "platform.h"
#include "test_common.h"

#include <doctest/doctest.h>
#include <fruit/fruit.h>
#include <memory>

namespace securefs::full_format
{
namespace
{
    fruit::Component<FuseHighLevelOpsBase> get_test_component(std::shared_ptr<OSService> os)
    {
        return fruit::createComponent()
            .bind<FuseHighLevelOpsBase, full_format::FuseHighLevelOps>()
            .install(full_format::get_table_io_component, 2)
            .registerProvider<fruit::Annotated<tSkipVerification, bool>()>([]() { return false; })
            .registerProvider<fruit::Annotated<tVerify, bool>()>([]() { return true; })
            .registerProvider<fruit::Annotated<tStoreTimeWithinFs, bool>()>([]() { return false; })
            .registerProvider<fruit::Annotated<tReadOnly, bool>()>([]() { return false; })
            .registerProvider([]() { return new BS::thread_pool(2); })
            .bind<Directory, BtreeDirectory>()
            .registerProvider<fruit::Annotated<tMaxPaddingSize, unsigned>()>([]() { return 0u; })
            .registerProvider<fruit::Annotated<tIvSize, unsigned>()>([]() { return 12u; })
            .registerProvider<fruit::Annotated<tBlockSize, unsigned>()>([]() { return 60u; })
            .registerProvider<fruit::Annotated<tMasterKey, key_type>()>([]()
                                                                        { return key_type(0x99); })
            .bindInstance(*os);
    }
    TEST_CASE("Full format test")
    {
        auto temp_dir_name = OSService::temp_name("tmp/full", "dir");
        OSService::get_default().ensure_directory(temp_dir_name, 0755);
        auto root = std::make_shared<OSService>(temp_dir_name);
        fruit::Injector<FuseHighLevelOpsBase> injector(get_test_component, root);
        testing::test_fuse_ops(injector.get<FuseHighLevelOpsBase&>(), *root);
    }
}    // namespace
}    // namespace securefs::full_format
