#pragma once

#include "myutils.h"
#include "object.h"

#include <memory>

#include <cryptopp/secblock.h>
#include <tclap/CmdLine.h>

namespace securefs
{
int commands_main(int argc, const char* const* argv);

class CommandBase : public Object
{
    DISABLE_COPY_MOVE(CommandBase)
public:
    CommandBase() = default;

    virtual const char* long_name() const noexcept = 0;
    virtual char short_name() const noexcept = 0;
    virtual const char* help_message() const noexcept = 0;
    TCLAP::CmdLine& cmdline()
    {
        if (!cmdline_)
        {
            cmdline_ = std::make_unique<TCLAP::CmdLine>(help_message());
        }
        return *cmdline_;
    }
    virtual void parse_cmdline(int argc, const char* const* argv);
    virtual int execute() = 0;

private:
    std::unique_ptr<TCLAP::CmdLine> cmdline_;
};
}    // namespace securefs
