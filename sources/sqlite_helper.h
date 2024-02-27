#pragma once
#include "platform.h"

#include <absl/strings/string_view.h>
#include <absl/types/span.h>
#include <sqlite3.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace securefs
{
class SQLiteDB
{
public:
    SQLiteDB() {}
    SQLiteDB(const char* filename, int flags, const char* vfs);

    void exec(const char* sql);

    sqlite3* get() noexcept { return ptr_ ? ptr_->db : nullptr; }
    explicit operator bool() const noexcept { return ptr_ && ptr_->db; }
    int64_t last_changes() noexcept { return sqlite3_changes64(get()); }
    Mutex& mutex()
    {
        if (!ptr_)
        {
            throw VFSException(EINVAL);
        }
        return ptr_->mu_;
    }

private:
    struct SQLiteDBWrapper
    {
        Mutex mu_;
        sqlite3* db = nullptr;
        SQLiteDBWrapper() {}
        SQLiteDBWrapper(SQLiteDBWrapper&&) = delete;
        ~SQLiteDBWrapper();
    };
    std::shared_ptr<SQLiteDBWrapper> ptr_;
};

class SQLiteStatement
{
public:
    SQLiteStatement() {}
    SQLiteStatement(SQLiteDB db, std::string sql);

    void reset();
    bool step();

    void bind_int(int column, int64_t value);
    void bind_text(int column, absl::string_view value);
    void bind_blob(int column, absl::Span<const unsigned char> value);

    int64_t get_int(int column);
    absl::string_view get_text(int column);
    absl::Span<const unsigned char> get_blob(int column);
    bool is_null(int column);

    explicit operator bool() const noexcept { return holder_.get(); }

private:
    SQLiteDB db_;
    std::string sql_;

    struct StatementCloser
    {
        void operator()(sqlite3_stmt* st) const noexcept
        {
            if (st)
                sqlite3_finalize(st);
        }
    };
    std::unique_ptr<sqlite3_stmt, StatementCloser> holder_;

    void prologue();
};

class SQLiteException : public std::runtime_error
{
public:
    explicit SQLiteException(int code);
    explicit SQLiteException(sqlite3* db, int code);
};

void check_sqlite_call(int code);
void check_sqlite_call(sqlite3* db, int code);
}    // namespace securefs
