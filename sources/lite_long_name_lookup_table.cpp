#include "lite_long_name_lookup_table.h"
#include "crypto.h"
#include "logger.h"

#include <absl/strings/str_cat.h>
#include <absl/strings/string_view.h>
#include <cryptopp/sha.h>

namespace securefs
{
std::string encrypt_long_name_component(AES_SIV& encryptor, absl::string_view long_name)
{
    unsigned char sha256[32];
    CryptoPP::SHA256 calc;
    calc.Update(reinterpret_cast<const byte*>(long_name.data()), long_name.size());
    calc.TruncatedFinal(sha256, sizeof(sha256));
    std::vector<unsigned char> buffer(sizeof(sha256) + AES_SIV::IV_SIZE);
    encryptor.encrypt_and_authenticate(
        sha256, sizeof(sha256), nullptr, 0, buffer.data() + AES_SIV::IV_SIZE, buffer.data());
    return absl::StrCat("_", hexify(buffer), "_");
}

LongNameLookupTable::LongNameLookupTable(StringRef filename, bool readonly)
{
    db_ = SQLiteDB(
        filename.c_str(),
        SQLITE_OPEN_NOMUTEX
            | (readonly ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)),
        nullptr);
    if (!readonly)
    {
        db_.exec(R"(
                create table if not exists encrypted_mappings (
                    encrypted_hash blob not null primary key,
                    encrypted_name blob not null
                );
            )");
    }
}

LongNameLookupTable::~LongNameLookupTable() {}

std::vector<unsigned char>
LongNameLookupTable::lookup(absl::Span<const unsigned char> encrypted_hash)
{
    SQLiteStatement q(db_,
                      "select encrypted_name from encrypted_mappings where encrypted_hash = ?;");
    q.reset();
    q.bind_blob(1, encrypted_hash);
    if (!q.step())
    {
        return {};
    }
    auto span = q.get_blob(0);
    return std::vector<unsigned char>(span.begin(), span.end());
}

void LongNameLookupTable::insert_or_update(absl::Span<const unsigned char> encrypted_hash,
                                           absl::Span<const unsigned char> encrypted_long_name)
{
    SQLiteStatement q(db_, R"(
            insert or ignore into encrypted_mappings
                (encrypted_hash, encrypted_name)
                values (?, ?);
        )");
    q.reset();
    q.bind_blob(1, encrypted_hash);
    q.bind_blob(2, encrypted_long_name);
    q.step();
}

void LongNameLookupTable::delete_once(absl::Span<const unsigned char> encrypted_hash)
{
    SQLiteStatement q(db_, R"(
            delete from encrypted_mappings
                where encrypted_hash = ?;
        )");
    q.reset();
    q.bind_blob(1, encrypted_hash);
    q.step();
}

void LongNameLookupTable::begin() { db_.exec("begin;"); }

void LongNameLookupTable::finish() noexcept
{
    try
    {
        if (std::uncaught_exception())
        {
            db_.exec("rollback");
        }
        else
        {
            db_.exec("commit");
        }
    }
    catch (const std::exception& e)
    {
        ERROR_LOG("Failed to commit or rollback: %s", e.what());
    }
}

}    // namespace securefs
