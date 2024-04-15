#include "fuse_tracer_v2.h"
#include "exceptions.h"
#include "stat_workaround.h"

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
        absl::Format(&sink, "%s", absl::FormatTime(absl::RFC3339_full, time, absl::UTCTimeZone()));
    }
    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const char*> value)
    {
        absl::Format(&sink, "\"%s\"", absl::Utf8SafeCEscape(value.value));
    }
    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const void*> value)
    {
        absl::Format(&sink, "%p", value.value);
    }
    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const fuse_stat*> value)
    {
        absl::Format(&sink,
                     "{st_size=%lld, st_mode=%#o, st_nlink=%lld, st_uid=%lld, st_gid=%lld, "
                     "st_blksize=%lld, st_blocks=%lld",
                     value.value->st_size,
                     value.value->st_mode,
                     value.value->st_nlink,
                     value.value->st_uid,
                     value.value->st_gid,
                     value.value->st_blksize,
                     value.value->st_blocks);

        auto atim = get_atim(*value.value);
        auto mtim = get_mtim(*value.value);
        auto ctim = get_ctim(*value.value);
        auto birthtime = get_birthtim(*value.value);
        absl::Format(&sink,
                     ", st_atim=%v, st_mtim=%v, st_ctim=%v",
                     Wrapped<const fuse_timespec*>{&atim},
                     Wrapped<const fuse_timespec*>{&mtim},
                     Wrapped<const fuse_timespec*>{&ctim});
        if (birthtime.has_value())
        {
            absl::Format(
                &sink, ", st_birthtim=%v", Wrapped<const fuse_timespec*>{&birthtime.value()});
        }
        absl::Format(&sink, "%c", '}');
    }
    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const fuse_file_info*> value)
    {
        absl::Format(&sink,
                     "{fh=0x%p, flags=%#o}",
                     reinterpret_cast<const void*>(value.value->fh),
                     value.value->flags);
    }
    template <typename Sink>
    void AbslStringify(Sink& sink, Wrapped<const fuse_statvfs*> value)
    {
        absl::Format(&sink,
                     "{f_bsize=%lld, f_frsize=%lld, f_blocks=%lld, f_bfree=%lld, f_bavail=%lld, "
                     "f_files=%lld, f_ffree=%lld, f_favail=%lld, f_fsid=%lld, f_flag=%lld, "
                     "f_namemax=%lld}",
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
    template <typename Sink, typename T>
    void AbslStringify(Sink& sink, Wrapped<T> value)
    {
        absl::Format(&sink, "%v", value.value);
    }
}    // namespace

void FuseTracer::print(FILE* fp, const WrappedFuseArg& arg)
{
    absl::FPrintF(fp, "%s=", arg.name);
    std::visit(
        [fp](auto value)
        {
            if constexpr (std::is_convertible_v<decltype(value), fuse_fill_dir_t>)
            {
                absl::FPrintF(fp, "%p", value);
            }
            else if constexpr (std::is_pointer_v<decltype(value)>)
            {
                if (value == nullptr)
                {
                    absl::FPrintF(fp, "%p", nullptr);
                }
                else
                {
                    absl::FPrintF(fp, "%v", Wrapped<decltype(value)>{value});
                }
            }
            else
            {
                absl::FPrintF(fp, "%v", value);
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
        absl::FPrintF(logger->m_fp, " and return code %lld", rc);
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
