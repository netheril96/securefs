#include "commands_v2.h"
#include "logger.h"

#include <args.hxx>
#include <cstdio>
#include <string>

namespace securefs
{
namespace
{

}

int commands_main_v2(int argc, const char* const* argv)
{
    args::ArgumentParser parser("securefs is an overlayed authenticated encryption filesystem.");
    args::CompletionFlag completion(parser, {"complete"});

    args::Group global_options(
        parser, "global flags", args::Group::Validators::DontCare, args::Options::Global);
    args::HelpFlag help(global_options, "help", "Show help", {'h', "help"});
    args::MapFlag<std::string, LoggingLevel> log_level(global_options,
                                                       "log-level",
                                                       "The logging level",
                                                       {"log-level"},
                                                       {{"TRACE", LoggingLevel::kLogTrace},
                                                        {"VERBOSE", LoggingLevel::kLogVerbose},
                                                        {"INFO", LoggingLevel::kLogInfo},
                                                        {"WARNING", LoggingLevel::kLogWarning},
                                                        {"ERROR", LoggingLevel::kLogError}},
                                                       LoggingLevel::kLogInfo);
    args::ValueFlag<std::string> log_file(
        global_options, "log-file", "The path to the log file. - for stderr.", {"log-file"}, "-");

    try
    {
        parser.ParseCLI(argc, argv);
    }
    catch (const args::Completion& e)
    {
        std::cout << e.what() << '\n';
        return 0;
    }
    catch (const args::Help&)
    {
        std::cout << parser;
        return 0;
    }
    catch (const args::ParseError& e)
    {
        std::cerr << e.what() << "\n\n" << parser;
        return 1;
    }
    return 0;
}
}    // namespace securefs
