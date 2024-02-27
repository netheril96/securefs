#pragma once

namespace securefs
{
const unsigned kOptionNoAuthentication = 0x1, kOptionReadOnly = 0x2, kOptionStoreTime = 0x4,
               kOptionCaseFoldFileName = 0x8, kOptionNFCFileName = 0x10, kOptionSkipDotDot = 0x20,
               kOptionNoNameTranslation = 0x40, kOptionLongNameComponent = 0x80;
}    // namespace securefs
