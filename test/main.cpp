#define DOCTEST_CONFIG_IMPLEMENT
#include "platform.h"
#include <doctest/doctest.h>

int main(int argc, char** argv)
{
#ifdef WIN32
    securefs::windows_init();
#endif
    securefs::OSService::get_default().ensure_directory("tmp", 0755);

    doctest::Context context;
    context.applyCommandLine(argc, argv);
    return context.run();
}
