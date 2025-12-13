#![cfg(windows)]

use std::{
    ffi::c_void,
    fmt::Debug,
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use winfsp::{
    U16CStr,
    filesystem::{FileSecurity, OpenFileInfo},
};

use crate::{
    OwnedFileDescriptor,
    lite::{
        LiteAesGcmCryptStreamFactory,
        long_name_db::{C_LONG_NAME_DB_FILENAME, LongNameLookupTable},
        name_translators::NameTranslator,
    },
    stream::{FileLikeStream, win::NtFileStream},
    tearc::Tearc,
    win::{NtError, OwnedUnicodeString},
    winfsp_wrappers::WinFspFileSystemCore,
};
use windows::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_DIRECTORY_FILE, FILE_NO_EA_KNOWLEDGE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
            FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FileAttributeTagInformation,
            NTCREATEFILE_CREATE_OPTIONS, NtCreateFile, NtQueryInformationFile,
            NtQuerySecurityObject,
        },
    },
    Win32::{
        Foundation::{HANDLE, OBJ_CASE_INSENSITIVE, OBJ_OPENLINK, OBJECT_ATTRIBUTE_FLAGS},
        Security::{
            DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR,
        },
        Storage::FileSystem::{
            FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_TAG_INFO,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, SYNCHRONIZE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
    core::Owned,
};

struct LiteDirLongNameDb {
    lookup_table: LongNameLookupTable,
    readonly: bool,
}

pub(super) struct LiteDirContext {
    dir: OwnedFileDescriptor,
    full_path: PathBuf,
    name_translator: Arc<dyn NameTranslator>,
    long_name_table: Mutex<Option<LiteDirLongNameDb>>,
}

impl Debug for LiteDirContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiteDirContext")
            .field("dir", &self.dir)
            .field("full_path", &self.full_path)
            .finish_non_exhaustive()
    }
}

impl LiteDirContext {
    fn init_long_name_db(
        &self,
        db: &mut Option<LiteDirLongNameDb>,
        readonly: bool,
    ) -> anyhow::Result<()> {
        let mut db_path = self.full_path.clone();
        db_path.push(C_LONG_NAME_DB_FILENAME.to_str()?);
        let lookup_table = LongNameLookupTable::new(
            db_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid db path"))?,
            readonly,
        )?;
        *db = Some(LiteDirLongNameDb {
            lookup_table,
            readonly,
        });
        Ok(())
    }

    pub(super) fn ensure_readable_long_name_db(
        &self,
    ) -> anyhow::Result<MappedMutexGuard<'_, LongNameLookupTable>> {
        let guard = self.long_name_table.lock();
        let map_result = MutexGuard::try_map_or_err(guard, |db| {
            if db.is_none() {
                self.init_long_name_db(db, true)?;
            }
            anyhow::Ok(&mut db.as_mut().unwrap().lookup_table)
        });
        match map_result {
            Ok(result) => anyhow::Ok(result),
            Err(err) => Err(err.1)?,
        }
    }

    pub(super) fn ensure_writable_long_name_db(
        &self,
    ) -> anyhow::Result<MappedMutexGuard<'_, LongNameLookupTable>> {
        let guard = self.long_name_table.lock();
        let map_result = MutexGuard::try_map_or_err(guard, |db| {
            if let Some(inner) = db
                && inner.readonly
            {
                *db = None;
            }
            if db.is_none() {
                self.init_long_name_db(db, false)?;
            }
            anyhow::Ok(&mut db.as_mut().unwrap().lookup_table)
        });
        match map_result {
            Ok(result) => anyhow::Ok(result),
            Err(err) => Err(err.1)?,
        }
    }
}

pub(super) struct LiteRegularFileContext {
    file_like_stream: Box<dyn FileLikeStream>,
    full_path: PathBuf,
}

impl Debug for LiteRegularFileContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiteRegularFileContext")
            .field("full_path", &self.full_path)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(super) enum LiteContext {
    Dir(LiteDirContext),
    File(LiteRegularFileContext),
}

fn get_file_attributes(handle: HANDLE) -> anyhow::Result<u32> {
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut file_attr_info: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &raw mut iosb,
            &raw mut file_attr_info as _,
            size_of_val(&file_attr_info).try_into()?,
            FileAttributeTagInformation,
        )
    };
    if status.0 < 0 {
        return Err(NtError { status }).context("calling NtQueryInformationFile failed");
    }
    Ok(file_attr_info.FileAttributes)
}

pub(super) struct LiteWinFspCore {
    root_dir: Tearc<LiteDirContext>,
    factory: LiteAesGcmCryptStreamFactory,
}

impl LiteWinFspCore {
    fn translate_full(&self, file_name: &U16CStr) -> anyhow::Result<(String, OwnedUnicodeString)> {
        let file_name = String::from_utf16(file_name.as_slice())?;
        let mut joined = String::with_capacity(file_name.len() * 2);
        for part in file_name.split('\\') {
            if part.trim().is_empty() {
                continue;
            }
            joined.push_str(str::from_utf8(
                self.root_dir
                    .name_translator
                    .encode_name(file_name.as_bytes())?
                    .as_slice(),
            )?);
            joined.push('\\');
        }
        if joined.ends_with("\\") {
            joined.pop();
        }
        let un = OwnedUnicodeString::try_from(joined.as_str())?;
        Ok((joined, un))
    }
}

impl WinFspFileSystemCore for LiteWinFspCore {
    type FileContext = LiteContext;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        mut security_descriptor: Option<&mut [c_void]>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> anyhow::Result<FileSecurity> {
        if let Some(security) = reparse_point_resolver(file_name) {
            return Ok(security);
        }

        let (_, encoded_un) = self.translate_full(file_name)?;
        let obj_attr = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>().try_into()?,
            RootDirectory: HANDLE(self.root_dir.dir.as_raw_handle()),
            ObjectName: &raw const encoded_un.unicode_string,
            Attributes: OBJECT_ATTRIBUTE_FLAGS::from(OBJ_CASE_INSENSITIVE | OBJ_OPENLINK),
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut handle = HANDLE(std::ptr::null_mut());
        let mut io_status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        let status = unsafe {
            NtCreateFile(
                &raw mut handle,
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                &raw const obj_attr,
                &raw mut io_status_block,
                None,
                FILE_FLAG_OPEN_REPARSE_POINT,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_OPEN_REPARSE_POINT,
                None,
                0,
            )
        };
        if status.0 < 0 {
            return Err(NtError { status }).context("calling NtCreateFile failed");
        }
        let handle = unsafe { Owned::<HANDLE>::new(handle) };
        let attributes = get_file_attributes(*handle)?;

        // cache file_attributes for Open
        unsafe {
            self.with_operation_response(|rsp| {
                rsp.Rsp.Create.Opened.FileInfo.FileAttributes = attributes;
            })
            .unwrap();
        }

        let mut sz_security_descriptor: u32 = 0;

        if let Some(ref mut security_descriptor) = security_descriptor {
            let status = unsafe {
                NtQuerySecurityObject(
                    *handle,
                    (OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION)
                        .0,
                    Some(PSECURITY_DESCRIPTOR(security_descriptor.as_mut_ptr())),
                    security_descriptor.len().try_into()?,
                    &raw mut sz_security_descriptor,
                )
            };
            if status.0 < 0 {
                return Err(NtError { status }).context("calling NtQuerySecurityObject failed");
            }
        }

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: sz_security_descriptor.try_into()?,
            attributes: attributes,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> anyhow::Result<Self::FileContext> {
        let is_directory = unsafe {
            self.with_operation_response(|ctx| {
                FILE_ATTRIBUTE_DIRECTORY.0 & ctx.Rsp.Create.Opened.FileInfo.FileAttributes != 0
            })
        }
        .unwrap_or(false);
        let mut create_options = NTCREATEFILE_CREATE_OPTIONS(create_options)
            & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE);

        let mut granted_access = FILE_ACCESS_RIGHTS(granted_access);
        if is_directory {
            granted_access |= SYNCHRONIZE;
            create_options |= FILE_SYNCHRONOUS_IO_NONALERT
        }

        let (encoded_name, encoded_un) = self.translate_full(file_name)?;

        let obj_attr = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>().try_into()?,
            RootDirectory: HANDLE(self.root_dir.dir.as_raw_handle()),
            ObjectName: &raw const encoded_un.unicode_string,
            Attributes: OBJECT_ATTRIBUTE_FLAGS::from(OBJ_CASE_INSENSITIVE | OBJ_OPENLINK),
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut handle = HANDLE(std::ptr::null_mut());
        let mut io_status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        let status = unsafe {
            NtCreateFile(
                &raw mut handle,
                granted_access | SYNCHRONIZE | FILE_GENERIC_READ,
                &raw const obj_attr,
                &raw mut io_status_block,
                None,
                FILE_FLAG_OPEN_REPARSE_POINT,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_OPEN_REPARSE_POINT,
                None,
                0,
            )
        };
        if status.0 < 0 {
            return Err(NtError { status }).context("calling NtCreateFile failed");
        }
        let handle = unsafe { OwnedFileDescriptor::from_raw_handle(handle.0) };
        let full_path = self
            .root_dir
            .full_path
            .join(Path::new(encoded_name.as_str()));

        let result = if is_directory {
            let ctx = LiteDirContext {
                dir: handle,
                full_path,
                name_translator: self.root_dir.name_translator.clone(),
                long_name_table: Mutex::new(None),
            };
            LiteContext::Dir(ctx)
        } else {
            let ctx = LiteRegularFileContext {
                file_like_stream: Box::new(self.factory.generic_wrap::<NtFileStream>(handle)?),
                full_path,
            };
            LiteContext::File(ctx)
        };

        Ok(result)
    }

    fn close(&self, context: Self::FileContext) {
        drop(context)
    }
}
