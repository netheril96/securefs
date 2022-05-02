#pragma once
#include "logger.h"
#include "platform.h"

#include <cstdio>
#include <type_traits>
#include <typeindex>
#include <typeinfo>

namespace securefs
{
struct WrappedFuseArg
{
    std::type_index type_index;
    const void* value;

    template <class T>
    WrappedFuseArg(T* value) : type_index(typeid(T)), value(value)
    {
    }
};

class FuseTracer
{
private:
    static void print(FILE* fp, const WrappedFuseArg& arg);
    static void print(FILE* fp, const WrappedFuseArg* args, size_t arg_size);

public:
    template <class ActualFunction>
    static inline auto traced_call(ActualFunction&& func,
                                   const char* funcsig,
                                   int lineno,
                                   const std::initializer_list<WrappedFuseArg>& args,
                                   Logger* logger = global_logger) -> decltype(func())
    {
        if (!logger)
        {
            return func();
        }
        if (logger->get_level() <= LoggingLevel::kLogTrace)
        {
            logger->prelog(LoggingLevel::kLogTrace, funcsig, lineno);
            fputs("Function starts with arguments ", logger->m_fp);
            print(logger->m_fp, args.begin(), args.size());
            logger->postlog(LoggingLevel::kLogTrace);
        }
        try
        {
            auto rc = func();
            if (logger->get_level() <= LoggingLevel::kLogTrace)
            {
                logger->prelog(LoggingLevel::kLogTrace, funcsig, lineno);
                fputs("Function ends with arguments ", logger->m_fp);
                print(logger->m_fp, args.begin(), args.size());
                fprintf(logger->m_fp, " and return code %lld", static_cast<long long>(rc));
                logger->postlog(LoggingLevel::kLogTrace);
            }
            return rc;
        }
        catch (const std::exception& e)
        {
            auto ebase = dynamic_cast<const ExceptionBase*>(&e);
            auto code = ebase ? ebase->error_number() : EPERM;
            if (logger->get_level() <= LoggingLevel::kLogError)
            {
                logger->prelog(LoggingLevel::kLogError, funcsig, lineno);
                fputs("Function fails with arguments ", logger->m_fp);
                print(logger->m_fp, args.begin(), args.size());
                fprintf(logger->m_fp,
                        " with return code %d because it encounters exception %s: %s",
                        -code,
                        get_type_name(e).get(),
                        e.what());
                logger->postlog(LoggingLevel::kLogError);
            }
            return -code;
        }
    }
};
}    // namespace securefs
