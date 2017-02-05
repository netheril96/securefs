#include "exceptions.h"
#include "logger.h"

securefs::ExceptionBase::ExceptionBase() {}

securefs::ExceptionBase::~ExceptionBase() {}

void ::securefs::throwVFSException(int errc) { throw VFSException(errc); }

void ::securefs::throwInvalidArgumentException(const char* why)
{
    throw InvalidArgumentException(why);
}

void ::securefs::throwInvalidArgumentException(std::string why)
{
    throw InvalidArgumentException(std::move(why));
}

securefs::VFSException::~VFSException() {}

securefs::POSIXException::~POSIXException() {}

securefs::InvalidArgumentException::~InvalidArgumentException(){}

    [[noreturn]] void securefs::throwFileTypeInconsistencyException()
{
    throw ::securefs::FileTypeInconsistencyException();
}

[[noreturn]] void securefs::throwPOSIXExceptionDoNotUseDirectly(int err, std::string msg)
{
    throw POSIXException(err, std::move(msg));
}

[[noreturn]] void securefs::throw_runtime_error(const char* msg) { throw std::runtime_error(msg); }

[[noreturn]] void securefs::throw_runtime_error(const std::string& msg)
{
    throw std::runtime_error(msg);
}
