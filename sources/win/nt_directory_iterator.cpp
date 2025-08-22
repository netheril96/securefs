#include "nt_directory_iterator.h"
#include "nt_exception.h"

namespace securefs
{
NTDirectoryIterator::NTDirectoryIterator(HANDLE dir_handle, ULONG buffer_size)
    : dir_handle_(dir_handle), buffer_size_(buffer_size)
{
    buffer_ = std::unique_ptr<BYTE[]>(new BYTE[buffer_size_]);
}

NTDirectoryIterator::~NTDirectoryIterator() = default;

void NTDirectoryIterator::rewind() { restart_scan_ = true; }

const FILE_ID_BOTH_DIR_INFO* NTDirectoryIterator::next()
{
    if (finished_)
        return nullptr;

    // If this is the first call or we've reached the end of current buffer
    if (current_entry_ == nullptr)
    {
        IO_STATUS_BLOCK iosb;
        NTSTATUS status = NtQueryDirectoryFile(
            dir_handle_,
            NULL,
            NULL,
            NULL,
            &iosb,
            buffer_.get(),
            buffer_size_,
            static_cast<FILE_INFORMATION_CLASS>(37) /*FileIdBothDirectoryInformation*/,
            FALSE,
            NULL,
            restart_scan_);
        restart_scan_ = false;

        if (status == STATUS_NO_MORE_FILES)
        {
            finished_ = true;
            return nullptr;
        }
        if (!NT_SUCCESS(status))
        {
            throw_nt_exception(status, "NtQueryDirectoryFile");
        }

        current_entry_ = reinterpret_cast<FILE_ID_BOTH_DIR_INFO*>(buffer_.get());
    }
    else
    {
        // Check if we've reached the end
        if (current_entry_->NextEntryOffset == 0)
        {
            current_entry_ = nullptr;
            // To query again
            return next();
        }
        // Move to next entry in the linked list
        BYTE* next_entry_ptr
            = reinterpret_cast<BYTE*>(current_entry_) + current_entry_->NextEntryOffset;

        current_entry_ = reinterpret_cast<FILE_ID_BOTH_DIR_INFO*>(next_entry_ptr);
    }

    return current_entry_;
}
}    // namespace securefs
