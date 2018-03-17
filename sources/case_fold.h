#pragma once

#include "mystring.h"

#include <stdint.h>

namespace securefs
{
uint32_t case_fold(uint32_t rune) noexcept;
std::string case_fold(StringRef str);
}    // namespace securefs
