use std::ffi::CStr;

use anyhow::Result;
use rusqlite::{Connection, OpenFlags, OptionalExtension};

pub const C_LONG_NAME_DB_FILENAME: &CStr = c".long_names.db";

// SQL queries (translated from C++ lite_long_name_lookup_table.cpp)
const CREATE_TABLE_SQL: &str = r#"
    create table if not exists encrypted_mappings (
        keyed_hash blob not null primary key,
        encrypted_name blob not null
    );
"#;
const UPDATE_MAPPING_SQL: &str = r#"
    insert or ignore into encrypted_mappings
        (keyed_hash, encrypted_name)
        values (?1, ?2);
"#;
const DELETE_MAPPING_SQL: &str = r#"
    delete from encrypted_mappings
        where keyed_hash = ?1;
"#;
const LOOKUP_MAPPING_SQL: &str = r#"
    select encrypted_name from encrypted_mappings where keyed_hash = ?1;
"#;
const LIST_HASHES_SQL: &str = r#"
    select keyed_hash from encrypted_mappings;
"#;

/// The table is needed when the file name component is so long that its
/// encrypted version no longer fits on most filesystems.
#[derive(Debug)]
pub struct LongNameLookupTable {
    conn: Connection,
    readonly: bool,
}

impl LongNameLookupTable {
    /// Creates a new `LongNameLookupTable` instance, opening or creating the
    /// underlying database file.
    ///
    /// If `readonly` is true, the database file must already exist.
    pub fn new(filename: &str, readonly: bool) -> Result<Self> {
        let flags = if readonly {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        };

        let conn = Connection::open_with_flags(filename, flags)?;

        if !readonly {
            conn.execute(CREATE_TABLE_SQL, [])?;
        }

        Ok(Self { conn, readonly })
    }

    /// Returns whether the database is opened in read-only mode.
    pub fn readonly(&self) -> bool {
        self.readonly
    }

    /// Looks up the encrypted name associated with a given keyed hash.
    pub fn lookup(&self, keyed_hash: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut stmt = self.conn.prepare_cached(LOOKUP_MAPPING_SQL)?;
        let result = stmt.query_row([keyed_hash], |row| row.get(0)).optional()?;
        Ok(result)
    }

    /// Updates or inserts a mapping between a keyed hash and an encrypted long
    /// name.
    pub fn update_mapping(&self, keyed_hash: &[u8], encrypted_long_name: &[u8]) -> Result<()> {
        self.conn
            .execute(UPDATE_MAPPING_SQL, [keyed_hash, encrypted_long_name])?;
        Ok(())
    }

    /// Removes a mapping associated with a given keyed hash.
    pub fn remove_mapping(&self, keyed_hash: &[u8]) -> Result<()> {
        self.conn.execute(DELETE_MAPPING_SQL, [keyed_hash])?;
        Ok(())
    }

    /// Lists all keyed hashes stored in the table.
    pub fn list_hashes(&self) -> Result<Vec<Vec<u8>>> {
        let mut stmt = self.conn.prepare(LIST_HASHES_SQL)?;
        let hashes = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<Vec<u8>>, _>>()?;
        Ok(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_long_name_lookup_table_in_memory() {
        // 1. Create a new table in an in-memory database.
        let table = LongNameLookupTable::new(":memory:", false).unwrap();

        // 2. Initially, it should be empty.
        assert!(table.list_hashes().unwrap().is_empty());
        assert_eq!(table.lookup(b"hash1").unwrap(), None);

        // 3. Update with some mappings.
        table
            .update_mapping(b"hash1", b"encrypted_long_name_1")
            .unwrap();
        table
            .update_mapping(b"hash2", b"encrypted_long_name_2")
            .unwrap();

        // 4. Verify lookups work.
        assert_eq!(
            table.lookup(b"hash1").unwrap(),
            Some(b"encrypted_long_name_1".to_vec())
        );
        assert_eq!(table.lookup(b"non_existent").unwrap(), None);

        // 5. Verify listing hashes.
        let mut hashes = table.list_hashes().unwrap();
        hashes.sort();
        assert_eq!(hashes, vec![b"hash1".to_vec(), b"hash2".to_vec()]);

        // 6. Remove a mapping and verify it's gone.
        table.remove_mapping(b"hash1").unwrap();
        assert_eq!(table.lookup(b"hash1").unwrap(), None);
        assert_eq!(table.list_hashes().unwrap(), vec![b"hash2".to_vec()]);
    }
}
