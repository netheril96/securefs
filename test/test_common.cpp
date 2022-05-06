#include "test_common.h"
#include "logger.h"

#include <cryptopp/osrng.h>

#include <cstdlib>

std::mt19937& get_random_number_engine()
{
    struct Initializer
    {
        std::mt19937 mt;

        Initializer()
        {
            uint32_t data[64];
            const char* seed = std::getenv("SECUREFS_TEST_SEED");
            if (seed && seed[0])
            {
                securefs::parse_hex(seed, reinterpret_cast<unsigned char*>(data), sizeof(data));
            }
            else
            {
                CryptoPP::OS_GenerateRandomBlock(
                    false, reinterpret_cast<unsigned char*>(data), sizeof(data));
            }
            INFO_LOG("Random seed: %s",
                     securefs::hexify(reinterpret_cast<const unsigned char*>(data), sizeof(data))
                         .c_str());
            std::seed_seq seq(std::begin(data), std::end(data));
            mt.seed(seq);
        }
    };

    static thread_local Initializer initializer;
    return initializer.mt;
}
