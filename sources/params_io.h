#pragma once

#include "params.pb.h"
#include "streams.h"

#include <string_view>

namespace securefs
{
DecryptedSecurefsParams decrypt(const LegacySecurefsJsonParams& legacy,
                                std::string_view password,
                                /* nullable */ StreamBase* key_stream);
}
