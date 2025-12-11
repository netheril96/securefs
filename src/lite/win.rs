#![cfg(windows)]

use std::{
    ffi::{OsString, c_void},
    os::windows::io::AsRawHandle,
    sync::Arc,
};

use anyhow::Context;
use parking_lot::Mutex;
use winfsp::{
    U16CStr,
    filesystem::{FileSecurity, OpenFileInfo},
};

use crate::{
    OwnedFileDescriptor,
    lite::{long_name_db::LongNameLookupTable, name_translators::NameTranslator},
    tearc::Tearc,
    win::{NtError, OwnedUnicodeString, to_winfsp_error},
};
use windows::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_OPEN, FILE_OPEN_REPARSE_POINT, FileAttributeTagInformation, NtCreateFile, NtQueryInformationFile, NtQuerySecurityObject,
        },
    },
    Win32::{
        Foundation::{HANDLE, OBJ_CASE_INSENSITIVE, OBJ_OPENLINK, OBJECT_ATTRIBUTE_FLAGS},
        Security::{
            DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR,
        },
        Storage::FileSystem::{
            FILE_ATTRIBUTE_TAG_INFO,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, READ_CONTROL,
        },
        System::IO::IO_STATUS_BLOCK,
    },
    core::Owned,
};

pub(super) struct LiteDirContext {
    dir: OwnedFileDescriptor,
    full_path: OsString,
    name_translator: Arc<dyn NameTranslator>,
    long_name_table: Mutex<LongNameLookupTable>,
}

pub(super) struct LiteRegularFileContext {}

pub(super) enum LiteContext {
    Dir(LiteDirContext),
    File(LiteRegularFileContext),
}

pub(super) struct LiteWinFspCore {
    root_dir: Tearc<LiteDirContext>,
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

impl winfsp::filesystem::FileSystemContext for LiteWinFspCore {
    type FileContext = LiteContext;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        mut security_descriptor: Option<&mut [c_void]>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        if let Some(security) = reparse_point_resolver(file_name) {
            return Ok(security);
        }

        let mut inner = || -> anyhow::Result<FileSecurity> {
            let file_name = String::from_utf16(file_name.as_slice())?;
            let encoded_name = self
                .root_dir
                .name_translator
                .encode_name(file_name.as_bytes())?;
            let encoded_un = OwnedUnicodeString::try_from(encoded_name.as_slice())?;
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
        };

        inner().map_err(|e| to_winfsp_error(&e))
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        todo!()
    }

    fn close(&self, context: Self::FileContext) {
        todo!()
    }
}
