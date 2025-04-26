#pragma once

#include <fuse.h>

namespace securefs
{
int my_fuse_main(int argc, char** argv, fuse_operations* op, void* user_data);
void clean_exit_fuse();
}    // namespace securefs
