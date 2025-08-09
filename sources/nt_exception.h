#pragma once
#ifdef _WIN32

#include "exceptions.h"

#include <winfsp/winfsp.h>

namespace securefs
{
NTSTATUS errno_to_ntstatus(int err);
int ntstatus_to_errno(NTSTATUS status);

class NTException : public SystemException
{
private:
    NTSTATUS m_status;
    std::string m_msg;

public:
    explicit NTException(NTSTATUS status, std::string msg) : m_status(status), m_msg(std::move(msg))
    {
    }

    NTSTATUS status() const noexcept { return m_status; }

    int error_number() const noexcept override { return ntstatus_to_errno(status()); }

    std::string message() const override;
};
}    // namespace securefs
#endif
