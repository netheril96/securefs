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

securefs::InvalidArgumentException::~InvalidArgumentException() {}

void securefs::throwFileTypeInconsistencyException()
{
    throw ::securefs::FileTypeInconsistencyException();
}
