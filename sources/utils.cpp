#include "utils.h"

#include <cryptopp/osrng.h>

namespace securefs
{
void generate_random(void* data, size_t size)
{
    thread_local CryptoPP::AutoSeededRandomPool pool;
    thread_local size_t total = 0;
    pool.GenerateBlock(static_cast<byte*>(data), size);
    total += size;
    if (total > 1024 * 1024)
    {
        total = 0;
        pool.Reseed();
    }
}
}
