#pragma once

#include "fuse_high_level_ops_base.h"
#include "params.pb.h"
#include <memory>

namespace securefs
{
std::shared_ptr<FuseHighLevelOpsBase>
make_fuse_high_level_ops(const DecryptedSecurefsParams& params, const MountOptions& mount_options);

int internal_mount(const InternalMountData& mount_data);
}    // namespace securefs
