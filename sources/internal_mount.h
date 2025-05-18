#pragma once

#include "full_format.h"
#include "fuse_high_level_ops_base.h"
#include "lite_format.h"
#include "params.pb.h"
#include "platform.h"

#include <memory>

namespace securefs
{
std::shared_ptr<FuseHighLevelOpsBase>
make_fuse_high_level_ops(std::shared_ptr<OSService> os_service,
                         const DecryptedSecurefsParams& params,
                         const MountOptions& mount_options);

std::shared_ptr<full_format::FuseHighLevelOps>
make_full_format_fuse_high_level_ops(std::shared_ptr<OSService> os_service,
                                     const DecryptedSecurefsParams& params,
                                     const MountOptions& mount_options);

std::shared_ptr<lite_format::FuseHighLevelOps>
make_lite_format_fuse_high_level_ops(std::shared_ptr<OSService> os_service,
                                     const DecryptedSecurefsParams& params,
                                     const MountOptions& mount_options);

int internal_mount(const InternalMountData& mount_data);
}    // namespace securefs
