# Long file name support

In full format, each filename can be up to 255 bytes long (in UTF-8 encoding). This is in line with most filesystems.

In lite format, each filename is encrypted by AES-SIV, and then converted by Base32. This means that a 143 bytes long filename will be transformed into a 255 bytes filename. Beyond that, the encrypted filename will exceed the maximum length on most filesystems.

Originally this will cause an error, but starting on securefs 1.0.0, we introduce long name support feature.

When filename length exceeds a predefined threshold (default: 128), it will be converted to an underlying filename by `Base32(Blake2b(name_master_key, filename))` plus three dots. Then this transformed name and the AES-SIV encrypted name will be stored in a per directory SQLite database. The database will be queried during `ls` call, and be updated when files are created, deleted or moved.

This approach has some performance penalty, but given the rarity of such long filenames, the tradeoff should make sense for most people.

## Migration
For lite format repositories created before `securefs` 1.0.0, they do not support long file names, but this can be fixed.
Run `securefs migrate-long-name` to perform the migration.

With the long file name support, we've also changed how symbolic links are encrypted. As a result, migration can only happen if the repository does not include symbolic links.
