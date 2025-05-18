#include "btree_dir.h"
#include "full_format.h"
#include "fuse_high_level_ops_base.h"
#include "internal_mount.h"
#include "mystring.h"
#include "params.pb.h"
#include "platform.h"
#include "tags.h"
#include "test_common.h"

#include <doctest/doctest.h>
#include <memory>

namespace securefs::full_format
{
namespace
{
    TEST_CASE("Full format test (case sensitive)")
    {
        auto temp_dir_name = OSService::temp_name("tmp/full", "dir");
        OSService::get_default().ensure_directory(temp_dir_name, 0755);
        auto root = std::make_shared<OSService>(temp_dir_name);
        DecryptedSecurefsParams params;
        params.mutable_size_params()->set_block_size(4096);
        params.mutable_size_params()->set_iv_size(16);
        params.mutable_size_params()->set_max_padding_size(0);
        params.mutable_full_format_params()->set_master_key("12345678901234567890123456789012");
        params.mutable_full_format_params()->set_case_insensitive(false);

        MountOptions mount_options;
        mount_options.set_enable_xattr(true);

        testing::test_fuse_ops(*make_full_format_fuse_high_level_ops(root, params, mount_options),
                               *root,
                               testing::CaseSensitivity::CaseSensitive,
                               testing::ResolveSymlinks::YES);
    }
    TEST_CASE("Full format test (case insensitive)")
    {
        auto temp_dir_name = OSService::temp_name("tmp/full", "dir");
        OSService::get_default().ensure_directory(temp_dir_name, 0755);
        auto root = std::make_shared<OSService>(temp_dir_name);
        DecryptedSecurefsParams params;
        params.mutable_size_params()->set_block_size(4096);
        params.mutable_size_params()->set_iv_size(16);
        params.mutable_size_params()->set_max_padding_size(0);
        params.mutable_full_format_params()->set_master_key("12345678901234567890123456789012");
        params.mutable_full_format_params()->set_case_insensitive(true);

        MountOptions mount_options;
        mount_options.set_enable_xattr(true);

        testing::test_fuse_ops(*make_full_format_fuse_high_level_ops(root, params, mount_options),
                               *root,
                               testing::CaseSensitivity::CaseInsensitive,
                               testing::ResolveSymlinks::YES);
    }
}    // namespace
}    // namespace securefs::full_format
