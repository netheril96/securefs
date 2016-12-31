#include "exceptions.h"

securefs::ExceptionBase::ExceptionBase() {}

securefs::ExceptionBase::~ExceptionBase() {}

void ::securefs::throwOSException(int errc) { throw OSException(errc); }

void ::securefs::throwPOSIXException(int errc, std::string msg)
{
    throw POSIXException(errc, std::move(msg));
}

void ::securefs::throwInvalidArgumentException(std::string why)
{
    throw InvalidArgumentException(std::move(why));
}

securefs::OSException::~OSException() {}

securefs::POSIXException::~POSIXException() {}

securefs::InvalidArgumentException::~InvalidArgumentException() {}
