#pragma once
#include "crypto.h"
#include "lock_guard.h"
#include "mystring.h"
#include "myutils.h"
#include "platform.h"
#include "sqlite_helper.h"

#include <absl/base/thread_annotations.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/string_view.h>

#include <vector>

namespace securefs
{
class ABSL_LOCKABLE LongNameLookupTable
{
public:
    LongNameLookupTable(const std::string& filename, bool readonly);
    ~LongNameLookupTable();

    std::vector<unsigned char> lookup(absl::Span<const unsigned char> encrypted_hash)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void insert_or_update(absl::Span<const unsigned char> encrypted_hash,
                          absl::Span<const unsigned char> encrypted_long_name)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void delete_once(absl::Span<const unsigned char> encrypted_hash)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);

    template <typename Callback>
    auto transact(Callback&& callback) -> decltype(callback(this))
    {
        LockGuard<LongNameLookupTable> lg(*this);
        return callback(this);
    }

    void lock() ABSL_EXCLUSIVE_LOCK_FUNCTION(*this) ABSL_NO_THREAD_SAFETY_ANALYSIS
    {
        db_.mutex().lock();
        begin();
    }

    void unlock() ABSL_UNLOCK_FUNCTION(*this) ABSL_NO_THREAD_SAFETY_ANALYSIS
    {
        finish();
        db_.mutex().unlock();
    }

private:
    SQLiteDB db_ ABSL_GUARDED_BY(*this);

private:
    void begin() ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
    void finish() noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(*this);
};

std::string encrypt_long_name_component(AES_SIV& encryptor, absl::string_view long_name);

}    // namespace securefs
