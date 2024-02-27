#pragma once
#include "crypto.h"
#include "mystring.h"
#include "myutils.h"
#include "platform.h"
#include "sqlite_helper.h"

#include <absl/strings/str_cat.h>
#include <absl/strings/string_view.h>

#include <vector>

namespace securefs
{
class LongNameLookupTable
{
public:
    LongNameLookupTable(StringRef filename, bool readonly);
    ~LongNameLookupTable();

    std::vector<unsigned char> lookup(absl::Span<const unsigned char> encrypted_hash)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);
    void insert_or_update(absl::Span<const unsigned char> encrypted_hash,
                          absl::Span<const unsigned char> encrypted_long_name)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);
    void delete_once(absl::Span<const unsigned char> encrypted_hash)
        ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);

    template <typename Callback>
    auto transact(Callback&& callback) -> decltype(callback(this))
    {
        LockGuard<Mutex> lg(mu_);
        begin();
        auto guard
            = stdex::make_guard([this]() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_) { this->finish(); });
        return callback(this);
    }

private:
    Mutex mu_;
    SQLiteDB db_ ABSL_GUARDED_BY(mu_);

private:
    void begin() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);
    void finish() noexcept ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);
};

std::string encrypt_long_name_component(AES_SIV& encryptor, absl::string_view long_name);

}    // namespace securefs
