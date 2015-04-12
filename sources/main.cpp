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
        auto fs = std::make_shared<securefs::POSIXFileStream>(fd);
        auto param = std::make_shared<securefs::SecureParam>();
        memset(param->key.data(), 0, param->key.size());
        memset(param->id.data(), 0, param->id.size());
        {
            auto hfs = securefs::make_stream_hmac(param, fs, true);
            hfs->write(tmp, 0, sizeof(tmp));
        }
        {
            auto hfs = securefs::make_stream_hmac(param, fs, true);
            char out[128] = {};
            hfs->read(out, 0, sizeof(out));
            fmt::print(stdout, "{}\n", out);
        }
        return Catch::Session().run(argc, argv);
    }
    catch (const std::exception& e)
    {
        fmt::print(stderr, "{}\n", e.what());
    }
}
