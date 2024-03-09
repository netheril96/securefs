#include "lite_long_name_lookup_table.h"
#include "logger.h"
#include "sqlite_helper.h"

#include <absl/strings/str_cat.h>
#include <cryptopp/sha.h>
#include <string_view>

namespace securefs
{

LongNameLookupTable::LongNameLookupTable(const std::string& filename, bool readonly)
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
                    encrypted_hash text not null primary key,
                    encrypted_name text not null
                );
            )");
    }
    db_.set_timeout(2000);
}

LongNameLookupTable::~LongNameLookupTable() {}

std::string LongNameLookupTable::lookup(std::string_view encrypted_hash)
{
    SQLiteStatement q(db_,
                      "select encrypted_name from encrypted_mappings where encrypted_hash = ?;");
    q.reset();
    q.bind_text(1, encrypted_hash);
    if (!q.step())
    {
        return {};
    }
    auto view = q.get_text(0);
    return {view.begin(), view.end()};
}

std::vector<std::string> LongNameLookupTable::list_hashes()
{
    SQLiteStatement q(db_, "select encrypted_hash from encrypted_mappings;");
    q.reset();
    std::vector<std::string> result;
    while (q.step())
    {
        result.emplace_back(q.get_text(0));
    }
    return result;
}

void LongNameLookupTable::insert_or_update(std::string_view encrypted_hash,
                                           std::string_view encrypted_long_name)
{
    SQLiteStatement q(db_, R"(
            insert or ignore into encrypted_mappings
                (encrypted_hash, encrypted_name)
                values (?, ?);
        )");
    q.reset();
    q.bind_text(1, encrypted_hash);
    q.bind_text(2, encrypted_long_name);
    q.step();
}

void LongNameLookupTable::delete_once(std::string_view encrypted_hash)
{
    SQLiteStatement q(db_, R"(
            delete from encrypted_mappings
                where encrypted_hash = ?;
        )");
    q.reset();
    q.bind_text(1, encrypted_hash);
    q.step();
}

void internal::LookupTableBase::begin() { db_.exec("begin;"); }

void internal::LookupTableBase::finish() noexcept
{
    try
    {
        if (has_uncaught_exceptions())
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

DoubleLongNameLookupTable::DoubleLongNameLookupTable(const std::string& from_dir_db,
                                                     const std::string& to_dir_db)
{
    db_ = SQLiteDB(from_dir_db.c_str(),
                   SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                   nullptr);
    db_.set_timeout(2000);
    {
        SQLiteStatement attacher(db_, "attach database ? as secondary;");
        attacher.bind_text(1, to_dir_db);
        attacher.step();
    }
    db_.exec(R"(
                create table if not exists main.encrypted_mappings (
                    encrypted_hash text not null primary key,
                    encrypted_name text not null
                );

                create table if not exists secondary.encrypted_mappings (
                    encrypted_hash text not null primary key,
                    encrypted_name text not null
                );
            )");
}

void DoubleLongNameLookupTable::remove_mapping_in_from_db(std::string_view encrypted_hash)
{
    SQLiteStatement q(db_, R"(
            delete from main.encrypted_mappings
                where encrypted_hash = ?;
        )");
    q.reset();
    q.bind_text(1, encrypted_hash);
    q.step();
}

void DoubleLongNameLookupTable::add_mapping_in_to_db(std::string_view encrypted_hash,
                                                     std::string_view encrypted_long_name)
{
    SQLiteStatement q(db_, R"(
            insert or ignore into secondary.encrypted_mappings
                (encrypted_hash, encrypted_name)
                values (?, ?);
        )");
    q.reset();
    q.bind_text(1, encrypted_hash);
    q.bind_text(2, encrypted_long_name);
    q.step();
}

}    // namespace securefs
