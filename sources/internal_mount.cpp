#include "internal_mount.h"
#include "btree_dir.h"
#include "file_table_v2.h"
#include "files.h"
#include "full_format.h"
#include "fuse_high_level_ops_base.h"
#include "tags.h"

#include <memory>

namespace securefs
{
namespace
{
    key_type from_byte_string(const std::string& key)
    {
        return key_type{reinterpret_cast<const uint8_t*>(key.data()), key.size()};
    }
    StrongType<key_type, tMasterKey> params_to_master_key(const DecryptedSecurefsParams& params)
    {
        return StrongType<key_type, tMasterKey>(
            from_byte_string(params.full_format_params().master_key()));
    }
    Directory::DirNameComparison
    params_to_dir_name_comparison(const DecryptedSecurefsParams& params)
    {
        const auto& p = params.full_format_params();
        if (p.case_insensitive() && p.unicode_normalization_agnostic())
        {
            return Directory::DirNameComparison{&case_uni_norm_insensitve_compare};
        }
        if (p.case_insensitive())
        {
            return Directory::DirNameComparison{&case_insensitive_compare};
        }
        if (p.unicode_normalization_agnostic())
        {
            return Directory::DirNameComparison{&uni_norm_insensitive_compare};
        }
        return Directory::DirNameComparison{&binary_compare};
    }
    std::shared_ptr<full_format::FileTable> make_file_table(std::shared_ptr<OSService> os_service,
                                                            const DecryptedSecurefsParams& params,
                                                            const MountOptions& mount_options)
    {
        full_format::FileTable::Factory<RegularFile> regular_file_factory
            = [=](std::shared_ptr<FileStream> file_stream,
                  std::shared_ptr<FileStream> meta_stream,
                  const id_type& id)
        {
            return std::make_unique<RegularFile>(
                std::move(file_stream),
                std::move(meta_stream),
                params_to_master_key(params),
                id,
                StrongType<bool, tVerify>(!mount_options.disable_verification()),
                StrongType<unsigned, tBlockSize>(params.size_params().block_size()),
                StrongType<unsigned, tIvSize>(params.size_params().iv_size()),
                StrongType<unsigned, tMaxPaddingSize>(params.size_params().max_padding_size()),
                StrongType<bool, tStoreTimeWithinFs>(params.full_format_params().store_time()));
        };
        full_format::FileTable::Factory<Directory> directory_factory
            = [=](std::shared_ptr<FileStream> file_stream,
                  std::shared_ptr<FileStream> meta_stream,
                  const id_type& id)
        {
            return std::make_unique<BtreeDirectory>(
                params_to_dir_name_comparison(params),
                std::move(file_stream),
                std::move(meta_stream),
                params_to_master_key(params),
                id,
                StrongType<bool, tVerify>(!mount_options.disable_verification()),
                StrongType<unsigned, tBlockSize>(params.size_params().block_size()),
                StrongType<unsigned, tIvSize>(params.size_params().iv_size()),
                StrongType<unsigned, tMaxPaddingSize>(params.size_params().max_padding_size()),
                StrongType<bool, tStoreTimeWithinFs>(params.full_format_params().store_time()));
        };
        full_format::FileTable::Factory<Symlink> symlink_factory
            = [=](std::shared_ptr<FileStream> file_stream,
                  std::shared_ptr<FileStream> meta_stream,
                  const id_type& id)
        {
            return std::make_unique<Symlink>(
                std::move(file_stream),
                std::move(meta_stream),
                params_to_master_key(params),
                id,
                StrongType<bool, tVerify>(!mount_options.disable_verification()),
                StrongType<unsigned, tBlockSize>(params.size_params().block_size()),
                StrongType<unsigned, tIvSize>(params.size_params().iv_size()),
                StrongType<unsigned, tMaxPaddingSize>(params.size_params().max_padding_size()),
                StrongType<bool, tStoreTimeWithinFs>(params.full_format_params().store_time()));
        };
        auto file_table_io = full_format::make_table_io(
            os_service,
            StrongType<bool, tLegacy>(params.full_format_params().legacy_file_table_io()),
            StrongType<bool, tReadOnly>(mount_options.read_only()));
        return std::make_shared<full_format::FileTable>(file_table_io,
                                                        std::move(regular_file_factory),
                                                        std::move(directory_factory),
                                                        std::move(symlink_factory));
    };
}    // namespace

std::shared_ptr<FuseHighLevelOpsBase>
make_fuse_high_level_ops(const DecryptedSecurefsParams& params, const MountOptions& mount_options);
}    // namespace securefs
