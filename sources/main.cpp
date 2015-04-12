#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"

#include "interfaces.h"
#include "exceptions.h"
#include "streams.h"

int main(int argc, char** argv)
{
    try
    {
        char tmp[] = "/tmp/abcdef.XXXXXX";
        int fd = ::mkstemp(tmp);
        securefs::POSIXFileStream s(fd);
        s.write(tmp, 0, sizeof(tmp));
        char out[sizeof(tmp)] = {};
        s.read(out, 0, sizeof(out));
        fmt::print(stdout, "{}\n", out);
        return Catch::Session().run(argc, argv);
    }
    catch (const std::exception& e)
    {
        fmt::print(stderr, "{}\n", e.what());
    }
}
