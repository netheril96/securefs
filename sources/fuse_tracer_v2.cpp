#include "fuse_tracer_v2.h"

#include <absl/strings/escaping.h>
#include <absl/strings/str_format.h>
#include <absl/time/time.h>

#include <ctime>
#include <type_traits>
#include <variant>

namespace securefs::trace
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
    const fuse_timespec* get_atim_helper(const StatClass*, ...)
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
    const fuse_timespec* get_mtim_helper(const StatClass*, ...)
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
    const fuse_timespec* get_ctim_helper(const StatClass*, ...)
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
    const fuse_timespec* get_birthtim_helper(const StatClass*, ...)
    {
        return nullptr;
    }

    template <typename T>
    struct Wrapped
    {
        T value;
    };

    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const fuse_timespec*> value)
    {
        auto time = absl::TimeFromTimespec(
            {value.value->tv_sec, static_cast<long>(value.value->tv_nsec)});
        static const absl::ParsedFormat<'v'> fmt("%v");
        absl::Format(&sink, fmt, time);
    }
    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const char*> value)
    {
        static const absl::ParsedFormat<'s'> fmt("\"%s\"");
        absl::Format(&sink, fmt, absl::Utf8SafeCEscape(value.value));
    }
    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const void*> value)
    {
        static const absl::ParsedFormat<'p'> fmt("%p");
        absl::Format(&sink, fmt, value.value);
    }
    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const fuse_stat*> value)
    {
        static const absl::ParsedFormat<'d', 'o', 'd', 'd', 'd', 'd', 'd'> fmt(
            "{st_size=%d, st_mode=%#o, st_nlink=%d, st_uid=%d, st_gid=%d, "
            "st_blksize=%d, st_blocks=%d");
        absl::Format(&sink,
                     fmt,
                     value.value->st_size,
                     value.value->st_mode,
                     value.value->st_nlink,
                     value.value->st_uid,
                     value.value->st_gid,
                     value.value->st_blksize,
                     value.value->st_blocks);
        if (auto atim = get_atim_helper(value.value, 0); atim)
        {
            static const absl::ParsedFormat<'v'> fmt(", st_atim=%v");
            absl::Format(&sink, fmt, Wrapped<const fuse_timespec*>{atim});
        }
        if (auto mtim = get_mtim_helper(value.value, 0); mtim)
        {
            static const absl::ParsedFormat<'v'> fmt(", st_mtim=%v");
            absl::Format(&sink, fmt, Wrapped<const fuse_timespec*>{mtim});
        }
        if (auto ctim = get_ctim_helper(value.value, 0); ctim)
        {
            static const absl::ParsedFormat<'v'> fmt(", st_ctim=%v");
            absl::Format(&sink, fmt, Wrapped<const fuse_timespec*>{ctim});
        }
        if (auto btim = get_birthtim_helper(value.value, 0); btim)
        {
            static const absl::ParsedFormat<'v'> fmt(", st_birthtim=%v");
            absl::Format(&sink, fmt, Wrapped<const fuse_timespec*>{btim});
        }
        static const absl::ParsedFormat<'c'> c("%c");
        absl::Format(&sink, c, '}');
    }
    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const fuse_file_info*> value)
    {
        static const absl::ParsedFormat<'p', 'o'> fmt("{fh=0x%p, flags=%#o}");
        absl::Format(
            &sink, fmt, reinterpret_cast<const void*>(value.value->fh), value.value->flags);
    }
    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const fuse_statvfs*> value)
    {
        absl::Format(&sink,
                     "{f_bsize=%d, f_frsize=%d, f_blocks=%d, f_bfree=%d, f_bavail=%d, "
                     "f_files=%d, f_ffree=%d, f_favail=%d, f_fsid=%d, f_flag=%d, "
                     "f_namemax=%d}",
                     value.value->f_bsize,
                     value.value->f_frsize,
                     value.value->f_blocks,
                     value.value->f_bfree,
                     value.value->f_bavail,
                     value.value->f_files,
                     value.value->f_ffree,
                     value.value->f_favail,
                     value.value->f_fsid,
                     value.value->f_flag,
                     value.value->f_namemax);
    }
}    // namespace

void FuseTracer::print(FILE* fp, const WrappedFuseArg& arg)
{
    absl::FPrintF(fp, "%s=", arg.name);
    std::visit(
        [fp](auto value)
        {
            static const absl::ParsedFormat<'v'> vfmt("%v");
            static const absl::ParsedFormat<'p'> pfmt("%p");

            if constexpr (std::is_convertible_v<decltype(value), fuse_fill_dir_t>)
            {
                absl::FPrintF(fp, pfmt, value);
            }
            else if constexpr (std::is_pointer_v<decltype(value)>)
            {
                if (value == nullptr)
                {
                    absl::FPrintF(fp, pfmt, nullptr);
                }
                else
                {
                    absl::FPrintF(fp, vfmt, Wrapped<decltype(value)>{value});
                }
            }
            else
            {
                absl::FPrintF(fp, vfmt, value);
            }
        },
        arg.value);
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
                                        int rc)
{
    if (logger && logger->get_level() <= LoggingLevel::kLogTrace)
    {
        logger->prelog(LoggingLevel::kLogTrace, funcsig, lineno);
        DEFER(logger->postlog(LoggingLevel::kLogTrace));

        fputs("Function ends with arguments ", logger->m_fp);
        print(logger->m_fp, args, arg_size);
        absl::FPrintF(logger->m_fp, " and return code %d", rc);
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
    if (!logger)
    {
        return;
    }
    if (logger->get_level() > LoggingLevel::kLogVerbose)
    {
        auto ee = dynamic_cast<const ExceptionBase*>(&e);
        if (ee && ee->error_number() == EEXIST)
        {
            // "Already exists" is a common error not worth logging.
            // Only logs it if logging level is verbose enough.
            return;
        }
    }
    if (logger->get_level() <= LoggingLevel::kLogError)
    {
        logger->prelog(LoggingLevel::kLogError, funcsig, lineno);
        DEFER(logger->postlog(LoggingLevel::kLogError));

        fputs("Function fails with arguments ", logger->m_fp);
        print(logger->m_fp, args, arg_size);
        absl::FPrintF(logger->m_fp,
                      " with return code %d because it encounters exception %s: %s",
                      rc,
                      get_type_name(e).get(),
                      e.what());
    }
}

}    // namespace securefs::trace
