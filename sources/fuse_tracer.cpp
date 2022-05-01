#include "fuse_tracer.h"

namespace securefs
{

void FuseTracer::print(FILE* fp, const WrappedFuseArg& arg)
{
    if (!arg.value)
    {
        fputs("null", fp);
        return;
    }
    if (arg.type_index == std::type_index(typeid(char)))
    {
        auto v = static_cast<const char*>(arg.value);
        fputs(v, fp);
    }
    else if (arg.type_index == std::type_index(typeid(fuse_stat)))
    {
        auto v = static_cast<const fuse_stat*>(arg.value);
        fprintf(fp, "{st_size=%lld}", static_cast<long long>(v->st_size));
    }
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
