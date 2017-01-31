#include "exceptions.h"
#include "logger.h"

securefs::ExceptionBase::ExceptionBase() {}

securefs::ExceptionBase::~ExceptionBase() {}

void ::securefs::throwVFSException(int errc) { throw VFSException(errc); }

void ::securefs::throwPOSIXException(int errc, std::string msg)
{
    global_logger->warn("POSIXException with code %d (%s) and message \"%s\" is about to be thrown",
                        errc,
                        sane_strerror(errc).c_str(),
                        msg.c_str());
    throw POSIXException(errc, std::move(msg));
}

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

securefs::InvalidArgumentException::~InvalidArgumentException() {}

void securefs::throwFileTypeInconsistencyException()
{
    throw ::securefs::FileTypeInconsistencyException();
}
