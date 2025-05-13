#pragma once

namespace securefs
{
struct tBlockSize
{
};
struct tIvSize
{
};
struct tMaxPaddingSize
{
};
struct tMasterKey
{
};
struct tNameMasterKey
{
};
struct tContentMasterKey
{
};
struct tXattrMasterKey
{
};
struct tPaddingMasterKey
{
};
struct tReadOnly
{
};
struct tVerify
{
};
struct tStoreTimeWithinFs
{
};
struct tLongNameThreshold
{
};
struct tCaseInsensitive
{
};
struct tEnableXattr
{
};
struct tInner
{
};
template <unsigned Layer>
struct tWrapped
{
};
}    // namespace securefs
