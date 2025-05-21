#include "commands.h"
#include "mystring.h"
#include "myutils.h"
#include "platform.h"

#include <absl/debugging/failure_signal_handler.h>
#include <absl/debugging/symbolize.h>

#include <clocale>

#ifdef _WIN32

int wmain(int argc, wchar_t** wargv)
{
    auto str_argv = securefs::make_unique_array<std::string>(argc);
    for (int i = 0; i < argc; ++i)
        str_argv[i] = securefs::narrow_string(wargv[i]);
    auto argv = securefs::make_unique_array<const char*>(argc + 1);
    for (int i = 0; i < argc; ++i)
        argv[i] = str_argv[i].c_str();
    argv[argc] = nullptr;

    absl::InitializeSymbolizer(argv[0]);
    absl::FailureSignalHandlerOptions options;
    options.use_alternate_stack = true;
    absl::InstallFailureSignalHandler(options);

    ::securefs::windows_init();
    return securefs::commands_main(argc, argv.get());
}

#else
int main(int argc, char** argv)
{
    absl::InitializeSymbolizer(argv[0]);
    absl::FailureSignalHandlerOptions options;
    options.use_alternate_stack = true;
    absl::InstallFailureSignalHandler(options);
    return securefs::commands_main(argc, argv);
}
#endif
