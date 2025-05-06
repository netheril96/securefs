#pragma once
#include "exceptions.h"
#include "logger.h"
#include "platform.h"    // IWYU pragma: keep

#include <cstdint>
#include <cstdio>
#include <variant>

namespace securefs::trace
{
struct RawBuffer
{
    const void* data;
    size_t size;
};
struct WrappedFuseArg
{
    absl::string_view name;
    std::variant<int,
                 unsigned,
                 int64_t,
                 uint64_t,
                 const void*,
                 const char*,
                 const fuse_timespec*,
                 const fuse_stat*,
                 const fuse_file_info*,
                 const fuse_statvfs*,
                 fuse_fill_dir_t,
                 RawBuffer>
        value;
};

class FuseTracer
{
private:
    static void print(FILE* fp, const WrappedFuseArg& arg);
    static void print(FILE* fp, const WrappedFuseArg* args, size_t arg_size);

    static void print_function_starts(Logger* logger,
                                      const char* funcsig,
                                      int lineno,
                                      const WrappedFuseArg* args,
                                      size_t arg_size);

    static void print_function_returns(Logger* logger,
                                       const char* funcsig,
                                       int lineno,
                                       const WrappedFuseArg* args,
                                       size_t arg_size,
                                       int rc);

    static void print_function_exception(Logger* logger,
                                         const char* funcsig,
                                         int lineno,
                                         const WrappedFuseArg* args,
                                         size_t arg_size,
                                         const std::exception& e,
                                         int rc);

public:
    template <class ActualFunction>
    static inline auto traced_call(ActualFunction&& func,
                                   const char* funcsig,
                                   int lineno,
                                   const std::initializer_list<WrappedFuseArg>& args,
                                   Logger* logger = global_logger) -> decltype(func())
    {
        print_function_starts(logger, funcsig, lineno, args.begin(), args.size());
        try
        {
            auto rc = func();
            print_function_returns(logger, funcsig, lineno, args.begin(), args.size(), rc);
            return rc;
        }
        catch (const VFSException& e)
        {
            int rc = -e.error_number();
            print_function_returns(logger, funcsig, lineno, args.begin(), args.size(), rc);
            return rc;
        }
        catch (const ExceptionBase& e)
        {
            int rc = -e.error_number();
            print_function_exception(logger, funcsig, lineno, args.begin(), args.size(), e, rc);
            return rc;
        }
        catch (const std::exception& e)
        {
            int rc = -EPERM;
            print_function_exception(logger, funcsig, lineno, args.begin(), args.size(), e, rc);
            return rc;
        }
    }
};
}    // namespace securefs::trace
