#include "tree_db.hpp"
#include "rng.hpp"
#include "utilities.hpp"

#include <absl/cleanup/cleanup.h>
#include <boost/numeric/conversion/cast.hpp>
#include <magic_enum.hpp>
#include <utf8proc.h>

namespace securefs
{
namespace
{
    constexpr utf8proc_option_t kCaseFold = UTF8PROC_CASEFOLD;
    constexpr utf8proc_option_t kUniNorm = UTF8PROC_COMPOSE;

    /// @brief A custom scalar SQLite function.
    /// The function takes a single text argument, and either case fold or perform unicode
    /// normalization on it. However, if the value is unchanged, the return value is NULL. This
    /// special behavior is to save storage when the original is already in its final form.
    void custom_sqlite_utfproc_map(sqlite3_context* ctx, int nArg, sqlite3_value** values)
    {
        if (nArg != 1)
        {
            return sqlite3_result_error_code(ctx, SQLITE_MISUSE);
        }
        auto option = *static_cast<const utf8proc_option_t*>(sqlite3_user_data(ctx));
        std::string_view input_text(reinterpret_cast<const char*>(sqlite3_value_text(values[0])),
                                    boost::numeric_cast<size_t>(sqlite3_value_bytes(values[0])));
        unsigned char* mapped = nullptr;
        auto size = utf8proc_map(reinterpret_cast<const unsigned char*>(input_text.data()),
                                 input_text.size(),
                                 &mapped,
                                 option);
        if (size <= 0)
        {
            return sqlite3_result_null(ctx);
        }
        if (std::string_view(reinterpret_cast<const char*>(mapped), size) == input_text)
        {
            free(mapped);
            return sqlite3_result_null(ctx);
        }
        return sqlite3_result_text64(
            ctx, reinterpret_cast<const char*>(mapped), size, &free, SQLITE_UTF8);
    }

}    // namespace

void TreeDB::create_tables(bool exact_only)
{
    db_.exec(R"(
            create table Entries (
                inode integer not null,
                parent_inode integer not null,
                name text not null,
                file_type integer not null,
                link_count integer not null
            );
            create index InodeOnEntries on Entries (inode);
            create unique index ParentNameOnEntries on Entries (parent_inode, name);
        )");
    if (!exact_only)
    {
        db_.exec(R"(
            alter table Entries add column casefolded_name as (casefold_if_changed(name));
            alter table Entries add column uninormed_name as (uninorm_if_changed(name));
            create index ParentCaseFoldedNameOnEntries on Entries (parent_inode, casefolded_name) 
                where casefolded_name is not null;
            create index ParentUniNormedNameOnEntries on Entries (parent_inode, uninormed_name)
                where uninormed_name is not null;
        )");
    }
}

int64_t TreeDB::create_entry(int64_t parent_inode, std::string_view name, FileType file_type)
{
    int64_t inode = 0;
    while (true)
    {
        generate_random(&inode, sizeof(inode));
        if (inode == 0)
        {
            continue;    // FUSE treats 0 inode as non-existent.
        }
        lookup_count_of_inode_.reset();
        lookup_count_of_inode_.step();
        if (lookup_count_of_inode_.get_int(0) == 0)
        {
            break;
        }
    }
    create_.reset();
    create_.bind_int(1, inode);
    create_.bind_int(2, parent_inode);
    create_.bind_text(3, name);
    create_.bind_int(4, magic_enum::enum_integer(file_type));
    create_.step();
    return inode;
}

std::optional<TreeDB::LookupResult>
TreeDB::lookup_entry(int64_t parent_inode, std::string_view name, NameLookupMode lookup_mode)
{
    C_unique_ptr<unsigned char> guard;
    SQLiteStatement* stmt = nullptr;

    switch (lookup_mode)
    {
    case NameLookupMode::EXACT:
        stmt = &lookup_exact_;
        break;
    case NameLookupMode::CASE_INSENSITIVE:
    {
        unsigned char* mapped = nullptr;
        auto mapped_size = utf8proc_map(
            reinterpret_cast<const unsigned char*>(name.data()), name.size(), &mapped, kCaseFold);
        if (mapped_size > 0)
        {
            guard.reset(mapped);
            name = std::string_view(reinterpret_cast<const char*>(mapped), mapped_size);
        }
        stmt = &lookup_case_insensitive_;
    }
    break;
    case NameLookupMode::UNINORM:
    {
        unsigned char* mapped = nullptr;
        auto mapped_size = utf8proc_map(
            reinterpret_cast<const unsigned char*>(name.data()), name.size(), &mapped, kUniNorm);
        if (mapped_size > 0)
        {
            guard.reset(mapped);
            name = std::string_view(reinterpret_cast<const char*>(mapped), mapped_size);
        }
        stmt = &lookup_uninormed_;
    }
    break;
    }

    std::optional<TreeDB::LookupResult> result;

    stmt->reset();
    stmt->bind_int(1, parent_inode);
    stmt->bind_text(2, name);
    if (!stmt->step())
    {
        return result;
    }
    result.emplace();
    result->inode = stmt->get_int(0);
    result->file_type = magic_enum::enum_cast<FileType>(stmt->get_int(1)).value();
    result->link_count = stmt->get_int(2);
    return result;
}

bool TreeDB::remove_entry(int64_t parent_inode, int64_t inode)
{
    decrement_link_count_.reset();
    decrement_link_count_.bind_int(1, inode);
    decrement_link_count_.step();
    int64_t last_changes = db_.last_changes();
    if (last_changes <= 0)
    {
        return false;
    }
    remove_.reset();
    remove_.bind_int(1, inode);
    remove_.bind_int(2, parent_inode);
    remove_.step();
    return last_changes == 1;
}

TreeDB::TreeDB(SQLiteDB db)
    : db_(std::move(db))
    , begin_(db_, "begin;")
    , commit_(db_, "commit;")
    , rollback_(db_, "rollback;")
    , lookup_count_of_inode_(db_, "select count(1) from Entries where inode = ?;")
    , lookup_exact_(db_, R"(
                select inode, file_type, link_count from Entries
                    where parent_inode = ? and name = ?;
            )")
    , lookup_case_insensitive_(db_, R"(
                select inode, file_type, link_count from Entries
                    where (parent_inode = ?1 and name = ?2)
                union
                select inode, file_type, link_count from Entries
                    where (parent_inode = ?1 and casefolded_name = ?2);
            )")
    , lookup_uninormed_(db_, R"(
                select inode, file_type, link_count from Entries
                    where (parent_inode = ?1 and name = ?2)
                union
                select inode, file_type, link_count from Entries
                    where (parent_inode = ?1 and uninormed_name = ?2);
            )")
    , create_(db_, R"(
        insert into Entries (inode, parent_inode, name, file_type, link_count)
            values (?, ?, ?, ?, 1);
        )")
    , decrement_link_count_(db_, R"(
        update Entries set link_count = link_count - 1 where inode = ?1;
    )")
    , remove_(db_, R"(
        delete from Entries where inode = ? and parent_inode = ?;
    )")
{
    check_sqlite_call(db_.get(),
                      sqlite3_create_function_v2(db_.get(),
                                                 "casefold_if_changed",
                                                 1,
                                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                                 (void*)&kCaseFold,
                                                 &custom_sqlite_utfproc_map,
                                                 nullptr,
                                                 nullptr,
                                                 SQLITE_STATIC));
    check_sqlite_call(db_.get(),
                      sqlite3_create_function_v2(db_.get(),
                                                 "uninorm_if_changed",
                                                 1,
                                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                                 (void*)&kUniNorm,
                                                 &custom_sqlite_utfproc_map,
                                                 nullptr,
                                                 nullptr,
                                                 SQLITE_STATIC));
}

void TreeDB::lock_and_enter_transaction()
{
    mu_.Lock();
    begin_.reset();
    begin_.step();
}

void TreeDB::leave_transaction_and_unlock(bool rollback)
{
    if (rollback)
    {
        rollback_.reset();
        rollback_.step();
    }
    else
    {
        commit_.reset();
        commit_.step();
    }
    mu_.Unlock();
}

}    // namespace securefs