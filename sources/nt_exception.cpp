// This file is licensed under GPLv3 rather than MIT, because it contains derivative of GPL works.

#ifdef _WIN32
#include "nt_exception.h"

#include <absl/strings/str_format.h>

namespace securefs
{
NTSTATUS errno_to_ntstatus(int err)
{
    // See also https://github.com/winfsp/winfsp/blob/master/src/dll/fuse/errno.i
    switch (err)
    {
    case 0:
        return STATUS_SUCCESS;
    case 1:
        return STATUS_ACCESS_DENIED;
    case 2:
        return STATUS_OBJECT_NAME_NOT_FOUND;
    case 3:
        return STATUS_PROCEDURE_NOT_FOUND;
    case 4:
        return STATUS_CANCELLED;
    case 5:
        return STATUS_IO_DEVICE_ERROR;
    case 6:
        return STATUS_FILE_INVALID;
    case 7:
        return STATUS_INSUFFICIENT_RESOURCES;
    case 8:
        return STATUS_INVALID_IMAGE_FORMAT;
    case 9:
        return STATUS_INVALID_HANDLE;
    case 12:
        return STATUS_INSUFFICIENT_RESOURCES;
    case 13:
        return STATUS_ACCESS_DENIED;
    case 14:
        return STATUS_ACCESS_VIOLATION;
    case 16:
        return STATUS_DEVICE_BUSY;
    case 17:
        return STATUS_OBJECT_NAME_COLLISION;
    case 18:
        return STATUS_NOT_SAME_DEVICE;
    case 19:
        return STATUS_NO_SUCH_DEVICE;
    case 20:
        return STATUS_NOT_A_DIRECTORY;
    case 21:
        return STATUS_FILE_IS_A_DIRECTORY;
    case 22:
        return STATUS_INVALID_PARAMETER;
    case 23:
        return STATUS_TOO_MANY_OPENED_FILES;
    case 24:
        return STATUS_TOO_MANY_OPENED_FILES;
    case 27:
        return STATUS_DISK_FULL;
    case 28:
        return STATUS_DISK_FULL;
    case 29:
        return STATUS_INVALID_PARAMETER;
    case 30:
        return STATUS_MEDIA_WRITE_PROTECTED;
    case 31:
        return STATUS_TOO_MANY_LINKS;
    case 32:
        return STATUS_PIPE_BROKEN;
    case 33:
        return STATUS_INVALID_PARAMETER;
    case 34:
        return STATUS_INVALID_PARAMETER;
    case 36:
        return STATUS_POSSIBLE_DEADLOCK;
    case 38:
        return STATUS_NAME_TOO_LONG;
    case 39:
        return STATUS_LOCK_NOT_GRANTED;
    case 40:
        return STATUS_INVALID_DEVICE_REQUEST;
    case 41:
        return STATUS_DIRECTORY_NOT_EMPTY;
    case 42:
        return STATUS_INVALID_PARAMETER;
    case 100:
        return STATUS_ADDRESS_ALREADY_ASSOCIATED;
    case 103:
        return STATUS_CONNECTION_ACTIVE;
    case 105:
        return STATUS_CANCELLED;
    case 106:
        return STATUS_CONNECTION_ABORTED;
    case 107:
        return STATUS_CONNECTION_REFUSED;
    case 108:
        return STATUS_CONNECTION_RESET;
    case 110:
        return STATUS_HOST_UNREACHABLE;
    case 113:
        return STATUS_CONNECTION_ACTIVE;
    case 114:
        return STATUS_REPARSE_POINT_NOT_RESOLVED;
    case 116:
        return STATUS_HOST_DOWN;
    case 117:
        return STATUS_CONNECTION_RESET;
    case 118:
        return STATUS_NETWORK_UNREACHABLE;
    case 119:
        return STATUS_INSUFFICIENT_RESOURCES;
    case 120:
        return STATUS_END_OF_FILE;
    case 121:
        return STATUS_CONNECTION_INVALID;
    case 126:
        return STATUS_CONNECTION_INVALID;
    case 128:
        return STATUS_INVALID_HANDLE;
    case 138:
        return STATUS_TRANSACTION_TIMED_OUT;
    }
    return STATUS_UNSUCCESSFUL;
}

int ntstatus_to_errno(NTSTATUS status)
{
    // This is the reverse of errno_to_ntstatus
    switch (status)
    {
    case STATUS_SUCCESS:
        return 0;
    case STATUS_ACCESS_DENIED:
        return 1;
    case STATUS_OBJECT_NAME_NOT_FOUND:
        return 2;
    case STATUS_PROCEDURE_NOT_FOUND:
        return 3;
    case STATUS_CANCELLED:
        return 4;
    case STATUS_IO_DEVICE_ERROR:
        return 5;
    case STATUS_FILE_INVALID:
        return 6;
    case STATUS_INSUFFICIENT_RESOURCES:
        return 7;
    case STATUS_INVALID_IMAGE_FORMAT:
        return 8;
    case STATUS_INVALID_HANDLE:
        return 9;
    case STATUS_ACCESS_VIOLATION:
        return 14;
    case STATUS_DEVICE_BUSY:
        return 16;
    case STATUS_OBJECT_NAME_COLLISION:
        return 17;
    case STATUS_NOT_SAME_DEVICE:
        return 18;
    case STATUS_NO_SUCH_DEVICE:
        return 19;
    case STATUS_NOT_A_DIRECTORY:
        return 20;
    case STATUS_FILE_IS_A_DIRECTORY:
        return 21;
    case STATUS_INVALID_PARAMETER:
        return 22;
    case STATUS_TOO_MANY_OPENED_FILES:
        return 23;
    case STATUS_DISK_FULL:
        return 27;
    case STATUS_MEDIA_WRITE_PROTECTED:
        return 30;
    case STATUS_TOO_MANY_LINKS:
        return 31;
    case STATUS_PIPE_BROKEN:
        return 32;
    case STATUS_POSSIBLE_DEADLOCK:
        return 36;
    case STATUS_NAME_TOO_LONG:
        return 38;
    case STATUS_LOCK_NOT_GRANTED:
        return 39;
    case STATUS_INVALID_DEVICE_REQUEST:
        return 40;
    case STATUS_DIRECTORY_NOT_EMPTY:
        return 41;
    case STATUS_ADDRESS_ALREADY_ASSOCIATED:
        return 100;
    case STATUS_CONNECTION_ACTIVE:
        return 103;
    case STATUS_CONNECTION_ABORTED:
        return 106;
    case STATUS_CONNECTION_REFUSED:
        return 107;
    case STATUS_CONNECTION_RESET:
        return 108;
    case STATUS_HOST_UNREACHABLE:
        return 110;
    case STATUS_REPARSE_POINT_NOT_RESOLVED:
        return 114;
    case STATUS_HOST_DOWN:
        return 116;
    case STATUS_NETWORK_UNREACHABLE:
        return 118;
    case STATUS_END_OF_FILE:
        return 120;
    case STATUS_CONNECTION_INVALID:
        return 121;
    case STATUS_TRANSACTION_TIMED_OUT:
        return 138;
    }
    return 5;    // EIO
}

std::string NTException::message() const
{
    return absl::StrFormat("NT error 0x%X: %s", m_status, m_msg);
}
}    // namespace securefs
#endif
