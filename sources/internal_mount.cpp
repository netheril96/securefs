#include "internal_mount.h"
#include "btree_dir.h"
#include "file_table_v2.h"
#include "files.h"
#include "full_format.h"
#include "fuse_high_level_ops_base.h"
#include "lite_format.h"
#include "platform.h"
#include "tags.h"

#include <memory>
#include <utility>

namespace securefs
{
namespace
{
    key_type from_byte_string(const std::string& key)
    {
        return key_type{reinterpret_cast<const uint8_t*>(key.data()), key.size()};
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
        auto master_key = StrongType<key_type, tMasterKey>(
            from_byte_string(params.full_format_params().master_key()));
        auto verify = StrongType<bool, tVerify>(!mount_options.disable_verification());
        auto block_size = StrongType<unsigned, tBlockSize>(params.size_params().block_size());
        auto iv_size = StrongType<unsigned, tIvSize>(params.size_params().iv_size());
        auto max_padding_size
            = StrongType<unsigned, tMaxPaddingSize>(params.size_params().max_padding_size());
        auto store_time
            = StrongType<bool, tStoreTimeWithinFs>(params.full_format_params().store_time());

        auto regular_file_factory = [=](std::shared_ptr<FileStream> file_stream,
                                        std::shared_ptr<FileStream> meta_stream,
                                        const id_type& id)
        {
            return std::make_unique<RegularFile>(std::move(file_stream),
                                                 std::move(meta_stream),
                                                 master_key,
                                                 id,
                                                 verify,
                                                 block_size,
                                                 iv_size,
                                                 max_padding_size,
                                                 store_time);
        };
        auto directory_factory = [=](std::shared_ptr<FileStream> file_stream,
                                     std::shared_ptr<FileStream> meta_stream,
                                     const id_type& id)
        {
            return std::make_unique<BtreeDirectory>(params_to_dir_name_comparison(params),
                                                    std::move(file_stream),
                                                    std::move(meta_stream),
                                                    master_key,
                                                    id,
                                                    verify,
                                                    block_size,
                                                    iv_size,
                                                    max_padding_size,
                                                    store_time);
        };
        auto symlink_factory = [=](std::shared_ptr<FileStream> file_stream,
                                   std::shared_ptr<FileStream> meta_stream,
                                   const id_type& id)
        {
            return std::make_unique<Symlink>(std::move(file_stream),
                                             std::move(meta_stream),
                                             master_key,
                                             id,
                                             verify,
                                             block_size,
                                             iv_size,
                                             max_padding_size,
                                             store_time);
        };
        auto file_table_io = full_format::make_table_io(
            os_service,
            StrongType<bool, tLegacy>(params.full_format_params().legacy_file_table_io()),
            StrongType<bool, tReadOnly>(mount_options.read_only()));
        return std::make_shared<full_format::FileTable>(std::move(file_table_io),
                                                        std::move(regular_file_factory),
                                                        std::move(directory_factory),
                                                        std::move(symlink_factory));
    };
    std::shared_ptr<full_format::FuseHighLevelOps>
    make_full_format_fuse_high_level_ops(std::shared_ptr<OSService> os_service,
                                         const DecryptedSecurefsParams& params,
                                         const MountOptions& mount_options)
    {
        auto file_table = make_file_table(os_service, params, mount_options);
        auto locker
            = std::make_shared<full_format::RepoLocker>(os_service, mount_options.read_only());
        OwnerOverride owner_override{};
        if (mount_options.has_uid_override())
        {
            owner_override.uid_override = mount_options.uid_override();
        }
        if (mount_options.has_gid_override())
        {
            owner_override.gid_override = mount_options.gid_override();
        }
        return std::make_shared<full_format::FuseHighLevelOps>(
            std::move(os_service),
            std::move(file_table),
            std::move(locker),
            owner_override,
            StrongType<bool, tCaseInsensitive>(params.full_format_params().case_insensitive()),
            StrongType<bool, tEnableXattr>(mount_options.enable_xattr()));
    }
    std::shared_ptr<lite_format::FuseHighLevelOps>
    make_lite_format_fuse_high_level_ops(std::shared_ptr<OSService> os_service,
                                         const DecryptedSecurefsParams& params,
                                         const MountOptions& mount_options)
    {
        // Extract keys from params

        const auto& lite_params = params.lite_format_params();
        auto content_master_key
            = StrongType<key_type, tContentMasterKey>(from_byte_string(lite_params.content_key()));
        auto padding_master_key
            = StrongType<key_type, tPaddingMasterKey>(from_byte_string(lite_params.padding_key()));
        auto name_master_key
            = StrongType<key_type, tNameMasterKey>(from_byte_string(lite_params.name_key()));
        auto xattr_master_key
            = StrongType<key_type, tXattrMasterKey>(from_byte_string(lite_params.xattr_key()));

        auto block_size = StrongType<unsigned, tBlockSize>(params.size_params().block_size());
        auto iv_size = StrongType<unsigned, tIvSize>(params.size_params().iv_size());
        auto max_padding_size
            = StrongType<unsigned, tMaxPaddingSize>(params.size_params().max_padding_size());
        auto verify = StrongType<bool, tVerify>(!mount_options.disable_verification());
        auto enable_xattr = StrongType<bool, tEnableXattr>(mount_options.enable_xattr());

        // StreamOpener
        auto opener = std::make_shared<lite_format::StreamOpener>(
            content_master_key, padding_master_key, block_size, iv_size, max_padding_size, verify);

        // NameNormalizationFlags
        lite_format::NameNormalizationFlags name_flags{};
        name_flags.no_op = mount_options.plain_text_names();
        name_flags.should_case_fold = mount_options.case_fold();
        name_flags.should_normalize_nfc = mount_options.unicode_normalize_nfc();
        name_flags.long_name_threshold = lite_params.long_name_threshold();

        // NameTranslator
        auto name_trans = lite_format::make_name_translator(name_flags, name_master_key);

        // XattrCryptor
        auto xattr = std::make_shared<lite_format::XattrCryptor>(xattr_master_key, iv_size, verify);

        // Construct and return FuseHighLevelOps
        return std::make_shared<lite_format::FuseHighLevelOps>(
            os_service, opener, name_trans, xattr, xattr_master_key, enable_xattr);
    }
}    // namespace

std::shared_ptr<FuseHighLevelOpsBase>
make_fuse_high_level_ops(std::shared_ptr<OSService> os_service,
                         const DecryptedSecurefsParams& params,
                         const MountOptions& mount_options)
{
    if (params.has_full_format_params())
    {
        return make_full_format_fuse_high_level_ops(std::move(os_service), params, mount_options);
    }
    else if (params.has_lite_format_params())
    {
        return make_lite_format_fuse_high_level_ops(std::move(os_service), params, mount_options);
    }
    throw std::runtime_error("Unsupported format");
}
}    // namespace securefs
