#pragma once

#include "ntdecls.h"
#include <memory>

namespace securefs
{
class NTDirectoryIterator
{
private:
    HANDLE dir_handle_;
    std::unique_ptr<BYTE[]> buffer_;
    FILE_ID_BOTH_DIR_INFO* current_entry_ = nullptr;
    ULONG buffer_size_;
    bool finished_ = false, restart_scan_ = true;

public:
    explicit NTDirectoryIterator(HANDLE dir_handle, ULONG buffer_size = 13755);
    ~NTDirectoryIterator();

    void rewind();

    const FILE_ID_BOTH_DIR_INFO* next();
};
}    // namespace securefs
