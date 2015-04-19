#include "utils.h"

#include <cryptopp/osrng.h>

namespace securefs
{
void generate_random(void* data, size_t size)
{
    thread_local CryptoPP::AutoSeededRandomPool pool;
    pool.GenerateBlock(static_cast<byte*>(data), size);
}
}
