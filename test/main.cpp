#define DOCTEST_CONFIG_IMPLEMENT
#include "platform.h"
#include <absl/debugging/failure_signal_handler.h>
#include <absl/debugging/symbolize.h>
#include <doctest/doctest.h>

int main(int argc, char** argv)
{
    absl::InitializeSymbolizer(argv[0]);
    absl::FailureSignalHandlerOptions options;
    options.use_alternate_stack = true;
    absl::InstallFailureSignalHandler(options);

#ifdef _WIN32
    securefs::windows_init();
#endif
    securefs::OSService::get_default().ensure_directory("tmp", 0755);

    doctest::Context context;
    context.applyCommandLine(argc, argv);
    return context.run();
}
