#include "file_table_v2.h"
#include "files.h"
#include "fuse_high_level_ops_base.h"
#include "platform.h"
#include <absl/strings/string_view.h>
#include <cstdint>
#include <fuse_common.h>
#include <optional>

namespace securefs::full_format
{

class FuseHighLevelOps : public ::securefs::FuseHighLevelOpsBase
{
public:
    INJECT(FuseHighLevelOps(OSService& root, FileTable& ft)) : root_(root), ft_(ft) {}

    void initialize(fuse_conn_info* info) override {}
    int vstatfs(const char* path, fuse_statvfs* buf, const fuse_context* ctx) override;
    int vgetattr(const char* path, fuse_stat* st, const fuse_context* ctx) override;
    int vfgetattr(const char* path,
                  fuse_stat* st,
                  fuse_file_info* info,
                  const fuse_context* ctx) override;
    int vopendir(const char* path, fuse_file_info* info, const fuse_context* ctx) override;
    int vreleasedir(const char* path, fuse_file_info* info, const fuse_context* ctx) override;
    int vreaddir(const char* path,
                 void* buf,
                 fuse_fill_dir_t filler,
                 fuse_off_t off,
                 fuse_file_info* info,
                 const fuse_context* ctx) override;
    int vcreate(const char* path,
                fuse_mode_t mode,
                fuse_file_info* info,
                const fuse_context* ctx) override;
    int vopen(const char* path, fuse_file_info* info, const fuse_context* ctx) override;
    int vrelease(const char* path, fuse_file_info* info, const fuse_context* ctx) override;
    int vread(const char* path,
              char* buf,
              size_t size,
              fuse_off_t offset,
              fuse_file_info* info,
              const fuse_context* ctx) override;
    int vwrite(const char* path,
               const char* buf,
               size_t size,
               fuse_off_t offset,
               fuse_file_info* info,
               const fuse_context* ctx) override;
    int vflush(const char* path, fuse_file_info* info, const fuse_context* ctx) override;
    int vftruncate(const char* path,
                   fuse_off_t len,
                   fuse_file_info* info,
                   const fuse_context* ctx) override;
    int vunlink(const char* path, const fuse_context* ctx) override;
    int vmkdir(const char* path, fuse_mode_t mode, const fuse_context* ctx) override;
    int vrmdir(const char* path, const fuse_context* ctx) override;
    int vchmod(const char* path, fuse_mode_t mode, const fuse_context* ctx) override;
    int vchown(const char* path, fuse_uid_t uid, fuse_gid_t gid, const fuse_context* ctx) override;
    int vsymlink(const char* to, const char* from, const fuse_context* ctx) override;
    int vlink(const char* src, const char* dest, const fuse_context* ctx) override;
    int vreadlink(const char* path, char* buf, size_t size, const fuse_context* ctx) override;
    int vrename(const char* from, const char* to, const fuse_context* ctx) override;
    int
    vfsync(const char* path, int datasync, fuse_file_info* info, const fuse_context* ctx) override;
    int vtruncate(const char* path, fuse_off_t len, const fuse_context* ctx) override;
    int vutimens(const char* path, const fuse_timespec* ts, const fuse_context* ctx) override;
    int vlistxattr(const char* path, char* list, size_t size, const fuse_context* ctx) override;
    int vgetxattr(const char* path,
                  const char* name,
                  char* value,
                  size_t size,
                  uint32_t position,
                  const fuse_context* ctx) override;
    int vsetxattr(const char* path,
                  const char* name,
                  const char* value,
                  size_t size,
                  int flags,
                  uint32_t position,
                  const fuse_context* ctx) override;
    int vremovexattr(const char* path, const char* name, const fuse_context* ctx) override;

private:
    OSService& root_;
    FileTable& ft_;

private:
    struct OpenBaseResult
    {
        FilePtrHolder file;
        std::string last_component;
    };

    OpenBaseResult open_base(absl::string_view path);
    FilePtrHolder create(absl::string_view path, unsigned mode, int type, int uid, int gid);
    std::optional<FilePtrHolder> open_all(absl::string_view path);

    FileBase* get_file(fuse_file_info* info)
    {
        return reinterpret_cast<FileBase*>(static_cast<uintptr_t>(info->fh));
    }

    void set_file(fuse_file_info* info, FileBase* fb)
    {
        info->fh = reinterpret_cast<uintptr_t>(fb);
    }
};
}    // namespace securefs::full_format
