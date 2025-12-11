#![cfg(windows)]

use std::{
    ffi::{OsString, c_void},
    sync::Arc,
};

use parking_lot::Mutex;
use winfsp::{
    U16CStr,
    filesystem::{FileSecurity, OpenFileInfo},
};

use crate::{
    OwnedFileDescriptor,
    lite::{long_name_db::LongNameLookupTable, name_translators::NameTranslator},
};

pub(super) struct LiteDirHandle {
    dir: OwnedFileDescriptor,
    full_path: OsString,
    name_translator: Arc<dyn NameTranslator>,
    long_name_table: Mutex<LongNameLookupTable>,
}

pub(super) struct LiteFileHandle {}

pub(super) struct LiteWinFspCore {}

pub(super) enum LiteContext {
    Dir(LiteDirHandle),
    File(LiteFileHandle),
}

impl winfsp::filesystem::FileSystemContext for LiteWinFspCore {
    type FileContext = LiteContext;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        todo!()
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
