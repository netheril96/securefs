#include "fuse_tracer.h"

#include <cctype>
#include <ctime>

namespace securefs
{
namespace details
{
    namespace
    {

        template <typename StatClass>
        auto get_atim_helper(const StatClass* st, int) -> decltype(&st->st_atim)
        {
            return &st->st_atim;
        }

        template <typename StatClass>
        auto get_atim_helper(const StatClass* st, double) -> decltype(&st->st_atimespec)
        {
            return &st->st_atimespec;
        }

        template <typename StatClass>
        const struct fuse_timespec* get_atim_helper(const StatClass*, ...)
        {
            return nullptr;
        }

        template <typename StatClass>
        auto get_mtim_helper(const StatClass* st, int) -> decltype(&st->st_mtim)
        {
            return &st->st_mtim;
        }

        template <typename StatClass>
        auto get_mtim_helper(const StatClass* st, double) -> decltype(&st->st_mtimespec)
        {
            return &st->st_mtimespec;
        }

        template <typename StatClass>
        const struct fuse_timespec* get_mtim_helper(const StatClass*, ...)
        {
            return nullptr;
        }

        template <typename StatClass>
        auto get_ctim_helper(const StatClass* st, int) -> decltype(&st->st_ctim)
        {
            return &st->st_ctim;
        }

        template <typename StatClass>
        auto get_ctim_helper(const StatClass* st, double) -> decltype(&st->st_ctimespec)
        {
            return &st->st_ctimespec;
        }

        template <typename StatClass>
        const struct fuse_timespec* get_ctim_helper(const StatClass*, ...)
        {
            return nullptr;
        }

        template <typename StatClass>
        auto get_birthtim_helper(const StatClass* st, int) -> decltype(&st->st_birthtim)
        {
            return &st->st_birthtim;
        }

        template <typename StatClass>
        auto get_birthtim_helper(const StatClass* st, double) -> decltype(&st->st_birthtimespec)
        {
            return &st->st_birthtimespec;
        }

        template <typename StatClass>
        const struct fuse_timespec* get_birthtim_helper(const StatClass*, ...)
        {
            return nullptr;
        }

        void print(FILE* fp, const int* v) { fprintf(fp, "%d", *v); }
        void print(FILE* fp, const unsigned* v) { fprintf(fp, "%u", *v); }
        void print(FILE* fp, const long* v) { fprintf(fp, "%ld", *v); }
        void print(FILE* fp, const unsigned long* v) { fprintf(fp, "%lu", *v); }
        void print(FILE* fp, const long long* v) { fprintf(fp, "%lld", *v); }
        void print(FILE* fp, const unsigned long long* v) { fprintf(fp, "%llu", *v); }

        void print(FILE* fp, const struct fuse_timespec* v)
        {
            std::tm tm;
#ifdef _WIN32
            if (gmtime_s(&tm, &v->tv_sec))
                return;
#else
            if (!gmtime_r(&v->tv_sec, &tm))
                return;
#endif
            char buffer[256] = {};
            std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
            fprintf(fp, "%s.%09d UTC", buffer, static_cast<int>(v->tv_nsec));
        }

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
                    "st_blksize=%lld, st_blocks=%lld",
                    static_cast<long long>(v->st_size),
                    static_cast<unsigned>(v->st_mode),
                    static_cast<long long>(v->st_nlink),
                    static_cast<long long>(v->st_uid),
                    static_cast<long long>(v->st_gid),
                    static_cast<long long>(v->st_blksize),
                    static_cast<long long>(v->st_blocks));

            auto atim = get_atim_helper(v, 0);
            if (atim)
            {
                fputs(", st_atim=", fp);
                ::securefs::details::print(fp, atim);
            }
            auto mtim = get_mtim_helper(v, 0);
            if (mtim)
            {
                fputs(", st_mtim=", fp);
                ::securefs::details::print(fp, mtim);
            }
            auto ctim = get_ctim_helper(v, 0);
            if (ctim)
            {
                fputs(", st_ctim=", fp);
                ::securefs::details::print(fp, ctim);
            }
            auto birthtim = get_birthtim_helper(v, 0);
            if (birthtim)
            {
                fputs(", st_birthtim=", fp);
                ::securefs::details::print(fp, birthtim);
            }
            fputc('}', fp);
        }

        void print(FILE* fp, const struct fuse_file_info* v)
        {
            fprintf(fp, "{fh=0x%p, flags=%#o}", (const void*)(v->fh), v->flags);
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
    SECUREFS_DISPATCH(struct fuse_timespec)
    else { fprintf(fp, "0x%p", arg.value); }
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

void FuseTracer::print_function_starts(
    Logger* logger, const char* funcsig, int lineno, const WrappedFuseArg* args, size_t arg_size)
{
    if (logger && logger->get_level() <= LoggingLevel::kLogTrace)
    {
        logger->prelog(LoggingLevel::kLogTrace, funcsig, lineno);
        DEFER(logger->postlog(LoggingLevel::kLogTrace));

        fputs("Function starts with arguments ", logger->m_fp);
        print(logger->m_fp, args, arg_size);
    }
}

void FuseTracer::print_function_returns(Logger* logger,
                                        const char* funcsig,
                                        int lineno,
                                        const WrappedFuseArg* args,
                                        size_t arg_size,
                                        long long rc)
{
    if (logger && logger->get_level() <= LoggingLevel::kLogTrace)
    {
        logger->prelog(LoggingLevel::kLogTrace, funcsig, lineno);
        DEFER(logger->postlog(LoggingLevel::kLogTrace));

        fputs("Function ends with arguments ", logger->m_fp);
        print(logger->m_fp, args, arg_size);
        fprintf(logger->m_fp, " and return code %lld", rc);
    }
}

void FuseTracer::print_function_exception(Logger* logger,
                                          const char* funcsig,
                                          int lineno,
                                          const WrappedFuseArg* args,
                                          size_t arg_size,
                                          const std::exception& e,
                                          int rc)
{
    if (logger && logger->get_level() <= LoggingLevel::kLogError)
    {
        logger->prelog(LoggingLevel::kLogError, funcsig, lineno);
        DEFER(logger->postlog(LoggingLevel::kLogError));

        fputs("Function fails with arguments ", logger->m_fp);
        print(logger->m_fp, args, arg_size);
        fprintf(logger->m_fp,
                " with return code %d because it encounters exception %s: %s",
                rc,
                get_type_name(e).get(),
                e.what());
    }
}

}    // namespace securefs
