#pragma once
#ifdef _WIN32
#include <Windows.h>

namespace securefs
{
#pragma warning(push)
#pragma warning(disable : 4191)
template <class FuncPointer>
inline FuncPointer get_proc_address(HMODULE h, const char* name) noexcept
{
    return reinterpret_cast<FuncPointer>(::GetProcAddress(h, name));
}
#pragma warning(pop)

}    // namespace securefs
#endif
