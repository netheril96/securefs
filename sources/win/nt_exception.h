#pragma once

#include "exceptions.h"

#include <winfsp/winfsp.h>

namespace securefs
{
NTSTATUS errno_to_ntstatus(int err);
int ntstatus_to_errno(NTSTATUS status);

class NTException final : public SystemException
{
private:
    NTSTATUS m_status;
    std::string m_msg;

public:
    explicit NTException(NTSTATUS status, std::string msg) : m_status(status), m_msg(std::move(msg))
    {
    }

    long ntstatus() const noexcept override { return m_status; }

    int error_number() const noexcept override { return ntstatus_to_errno(ntstatus()); }

    std::string message() const override;
};

[[noreturn]] void throw_nt_exception(NTSTATUS status, std::string msg);

#define NT_CHECK_CALL(exp)                                                                         \
    do                                                                                             \
    {                                                                                              \
        NTSTATUS status = (exp);                                                                   \
        if (!NT_SUCCESS(status))                                                                   \
        {                                                                                          \
            throw_nt_exception(status, #exp);                                                      \
        }                                                                                          \
    } while (0)

class WindowsException : public SystemException
{
private:
    DWORD err;
    const wchar_t* funcname;
    std::wstring path1, path2;

public:
    explicit WindowsException(DWORD err,
                              const wchar_t* funcname,
                              std::wstring path1,
                              std::wstring path2);
    explicit WindowsException(DWORD err, const wchar_t* funcname, std::wstring path);
    explicit WindowsException(DWORD err, const wchar_t* funcname);
    ~WindowsException();

    std::string message() const override;
    DWORD win32_code() const noexcept;
    long ntstatus() const noexcept override;
    int error_number() const noexcept override;
};

[[noreturn]] void throw_windows_exception(const wchar_t* funcname);

#define THROW_WINDOWS_EXCEPTION(err, exp)                                                          \
    do                                                                                             \
    {                                                                                              \
        DWORD code = err;                                                                          \
        throw WindowsException(code, exp);                                                         \
    } while (0)

#define THROW_WINDOWS_EXCEPTION_WITH_PATH(err, exp, path)                                          \
    do                                                                                             \
    {                                                                                              \
        DWORD code = err;                                                                          \
        throw WindowsException(code, exp, path);                                                   \
    } while (0)

#define THROW_WINDOWS_EXCEPTION_WITH_TWO_PATHS(err, exp, path1, path2)                             \
    do                                                                                             \
    {                                                                                              \
        DWORD code = err;                                                                          \
        throw WindowsException(code, exp, path1, path2);                                           \
    } while (0)

#define WIN_CHECK_CALL(exp)                                                                        \
    if (!(exp))                                                                                    \
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"" #exp);
}    // namespace securefs
