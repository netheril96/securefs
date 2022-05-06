#include "test_common.h"

#include <cryptopp/osrng.h>

std::mt19937& get_random_number_engine()
{
    struct Initializer
    {
        std::mt19937 mt;

        Initializer()
        {
            uint32_t data[64];
            CryptoPP::OS_GenerateRandomBlock(
                false, reinterpret_cast<unsigned char*>(data), sizeof(data));
            std::seed_seq seq(std::begin(data), std::end(data));
            mt.seed(seq);
        }
    };

    static thread_local Initializer initializer;
    return initializer.mt;
}
