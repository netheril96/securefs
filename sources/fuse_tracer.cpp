#include "fuse_tracer.h"

#include <cctype>

namespace securefs
{
namespace details
{
    namespace
    {
        void print(FILE* fp, const int* v) { fprintf(fp, "%d", *v); }
        void print(FILE* fp, const unsigned* v) { fprintf(fp, "%u", *v); }
        void print(FILE* fp, const long* v) { fprintf(fp, "%ld", *v); }
        void print(FILE* fp, const unsigned long* v) { fprintf(fp, "%lu", *v); }
        void print(FILE* fp, const long long* v) { fprintf(fp, "%lld", *v); }
        void print(FILE* fp, const unsigned long long* v) { fprintf(fp, "%llu", *v); }

        void print(FILE* fp, const char* v)
        {
            fputc('\"', fp);
            while (*v)
            {
                int ch = *v;
                switch (ch)
                {
                case '\"':
                    fputs("\\\"", fp);
                    break;
                case '\'':
                    fputs("\\\'", fp);
                    break;
                case '\\':
                    fputs("\\\\", fp);
                    break;
                case '\a':
                    fputs("\\a", fp);
                    break;
                case '\b':
                    fputs("\\b", fp);
                    break;
                case '\n':
                    fputs("\\n", fp);
                    break;
                case '\t':
                    fputs("\\t", fp);
                    break;
                case '\f':
                    fputs("\\f", fp);
                    break;
                default:
                    if (ch > 0 && std::iscntrl(ch))
                        fprintf(fp, "\\x%02x", ch);
                    else
                        fputc(ch, fp);
                }
                ++v;
            }
            fputc('\"', fp);
        }

        void print(FILE* fp, const struct fuse_stat* v)
        {
            fprintf(fp,
                    "{st_size=%lld, st_mode=%#o, st_nlink=%lld, st_uid=%lld, st_gid=%lld, "
                    "st_blksize=%lld, st_blocks=%lld}",
                    static_cast<long long>(v->st_size),
                    static_cast<unsigned>(v->st_mode),
                    static_cast<long long>(v->st_nlink),
                    static_cast<long long>(v->st_uid),
                    static_cast<long long>(v->st_gid),
                    static_cast<long long>(v->st_blksize),
                    static_cast<long long>(v->st_blocks));
        }

        void print(FILE* fp, const struct fuse_file_info* v)
        {
            fprintf(fp, "{fh=%p, flags=%#o}", (const void*)(v->fh), v->flags);
        }

        void print(FILE* fp, const struct fuse_statvfs* v)
        {
            fprintf(fp,
                    "{f_bsize=%lld, f_frsize=%lld, f_blocks=%lld, f_bfree=%lld, f_bavail=%lld, "
                    "f_files=%lld, f_ffree=%lld, f_favail=%lld, f_fsid=%lld, f_flag=%lld, "
                    "f_namemax=%lld}",
                    static_cast<long long>(v->f_bsize),
                    static_cast<long long>(v->f_frsize),
                    static_cast<long long>(v->f_blocks),
                    static_cast<long long>(v->f_bfree),
                    static_cast<long long>(v->f_bavail),
                    static_cast<long long>(v->f_files),
                    static_cast<long long>(v->f_ffree),
                    static_cast<long long>(v->f_favail),
                    static_cast<long long>(v->f_fsid),
                    static_cast<long long>(v->f_flag),
                    static_cast<long long>(v->f_namemax));
        }
    }    // namespace
}    // namespace details
void FuseTracer::print(FILE* fp, const WrappedFuseArg& arg)
{
    if (!arg.value)
    {
        fputs("null", fp);
        return;
    }
#define SECUREFS_DISPATCH(type)                                                                    \
    else if (arg.type_index == std::type_index(typeid(type)))                                      \
    {                                                                                              \
        ::securefs::details::print(fp, static_cast<const type*>(arg.value));                       \
    }

    if (0)
    {
    }
    SECUREFS_DISPATCH(char)
    SECUREFS_DISPATCH(struct fuse_stat)
    SECUREFS_DISPATCH(int)
    SECUREFS_DISPATCH(unsigned)
    SECUREFS_DISPATCH(long)
    SECUREFS_DISPATCH(unsigned long)
    SECUREFS_DISPATCH(long long)
    SECUREFS_DISPATCH(unsigned long long)
    SECUREFS_DISPATCH(struct fuse_file_info)
    SECUREFS_DISPATCH(struct fuse_statvfs)
    else { fprintf(fp, "%p", arg.value); }
#undef SECUREFS_DISPATCH
}

void FuseTracer::print(FILE* fp, const WrappedFuseArg* args, size_t arg_size)
{
    fputc('(', fp);
    for (size_t i = 0; i < arg_size; ++i)
    {
        if (i)
        {
            fputs(", ", fp);
        }
        print(fp, args[i]);
    }
    fputc(')', fp);
}

}    // namespace securefs
