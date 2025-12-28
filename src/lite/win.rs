#![cfg(windows)]

use std::{
    ffi::c_void,
    fmt::Debug,
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{AssertOk, lite::IoWrapperFactory, winfsp_wrappers::TracedWinFspWrapper};
use crate::{
    OwnedFileDescriptor,
    lite::{
        long_name_db::{C_LONG_NAME_DB_FILENAME, LongNameLookupTable},
        name_translators::NameTranslator,
    },
    stream::{FileLikeStream, with_source_locked},
    win::{NtError, OwnedUnicodeString},
    winfsp_wrappers::WinFspFileSystemCore,
};
use crate::{
    lite::{LiteAesGcmCryptStreamFactory, name_translators::create_name_translator},
    protos::params::InternalMountData,
};
use ambassador::{Delegate, delegatable_trait};
use anyhow::Context;
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use widestring::u16cstr;
use windows::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NO_EA_KNOWLEDGE, FILE_NON_DIRECTORY_FILE,
            FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_STAT_INFORMATION,
            FILE_SYNCHRONOUS_IO_NONALERT, FileAttributeTagInformation, FileStatInformation,
            NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS, NtCreateFile,
            NtQueryInformationFile, NtQuerySecurityObject, RtlDosPathNameToNtPathName_U_WithStatus,
        },
    },
    Win32::{
        Foundation::{
            HANDLE, OBJ_CASE_INSENSITIVE, STATUS_FILE_IS_A_DIRECTORY, STATUS_INVALID_PARAMETER,
            STATUS_NOT_CAPABLE, UNICODE_STRING,
        },
        Security::{
            DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR,
        },
        Storage::FileSystem::{
            FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_TAG_INFO,
            FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_LIST_DIRECTORY,
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FILE_TRAVERSE, READ_CONTROL, SYNCHRONIZE,
        },
        System::{IO::IO_STATUS_BLOCK, WindowsProgramming::RtlFreeUnicodeString},
    },
    core::PWSTR,
};
use winfsp::{
    FspError, U16CStr, U16CString,
    filesystem::{FileInfo, FileSecurity, OpenFileInfo},
    host::{FileSystemHost, MountPoint, VolumeParams},
    service::FileSystemServiceBuilder,
    winfsp_init_or_die,
};

#[delegatable_trait]
trait FileInfoExt {
    fn get_file_info(&self) -> anyhow::Result<FileInfo>;
}

impl FileInfoExt for HANDLE {
    fn get_file_info(&self) -> anyhow::Result<FileInfo> {
        let mut st: FILE_STAT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };

        unsafe {
            NtQueryInformationFile(
                *self,
                &raw mut iosb,
                &raw mut st as _,
                size_of_val(&st) as u32,
                FileStatInformation,
            )
        }
        .assert_ok()
        .context("NtQueryInformationFile")?;

        Ok(FileInfo {
            file_attributes: st.FileAttributes,
            reparse_tag: st.ReparseTag,
            allocation_size: st.AllocationSize as _,
            file_size: st.EndOfFile as _,
            creation_time: st.CreationTime as _,
            last_access_time: st.LastAccessTime as _,
            last_write_time: st.LastWriteTime as _,
            change_time: st.ChangeTime as _,
            index_number: st.FileId as _,
            hard_links: 0,
            ea_size: 0,
        })
    }
}

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

impl FileInfoExt for LiteDirContext {
    fn get_file_info(&self) -> anyhow::Result<FileInfo> {
        HANDLE(self.dir.as_raw_handle()).get_file_info()
    }
}

pub(super) struct LiteRegularFileContext {
    file_like_stream: Mutex<Box<dyn FileLikeStream>>,
    full_path: PathBuf,
}

impl Debug for LiteRegularFileContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiteRegularFileContext")
            .field("full_path", &self.full_path)
            .finish_non_exhaustive()
    }
}

impl LiteRegularFileContext {
    fn with_source_lock<F, R>(&self, f: F) -> anyhow::Result<R>
    where
        F: FnOnce(&mut (dyn FileLikeStream + 'static)) -> anyhow::Result<R>,
    {
        let mut stream = self.file_like_stream.lock();
        with_source_locked(&mut **stream, f)
    }
}

impl FileInfoExt for LiteRegularFileContext {
    fn get_file_info(&self) -> anyhow::Result<FileInfo> {
        self.with_source_lock(|stream| {
            let mut info = stream.as_win_handle().get_file_info()?;
            info.file_size = stream.size()?;
            Ok(info)
        })
    }
}

#[derive(Debug, Delegate)]
#[delegate(FileInfoExt)]
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
    }
    .assert_ok()
    .context("calling NtQueryInformationFile failed")?;
    Ok(file_attr_info.FileAttributes)
}

pub(super) struct LiteWinFspCore {
    root_dir: LiteDirContext,
    factory: Box<dyn IoWrapperFactory>,
}

impl LiteWinFspCore {
    fn translate_full(&self, file_name: &U16CStr) -> anyhow::Result<(String, OwnedUnicodeString)> {
        let file_name = file_name.to_string()?;
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

    fn nt_create_file(
        &self,
        file_name: &U16CStr,
        desired_access: FILE_ACCESS_RIGHTS,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        create_disposition: NTCREATEFILE_CREATE_DISPOSITION,
        create_options: NTCREATEFILE_CREATE_OPTIONS,
        security_descriptor: PSECURITY_DESCRIPTOR,
    ) -> anyhow::Result<(OwnedFileDescriptor, String)> {
        let (encoded_name, encoded_un) = self.translate_full(file_name)?;

        let obj_attr = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>().try_into()?,
            RootDirectory: HANDLE(self.root_dir.dir.as_raw_handle()),
            ObjectName: &raw const encoded_un.unicode_string,
            Attributes: (OBJ_CASE_INSENSITIVE),
            SecurityDescriptor: security_descriptor.0 as _,
            SecurityQualityOfService: std::ptr::null(),
        };

        let mut handle = HANDLE::default();
        let mut io_status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };

        unsafe {
            NtCreateFile(
                &raw mut handle,
                desired_access | FILE_READ_ATTRIBUTES | READ_CONTROL,
                &raw const obj_attr,
                &raw mut io_status_block,
                None,
                file_attributes,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                create_disposition,
                create_options,
                None,
                0,
            )
        }
        .assert_ok()
        .context("NtCreateFile")?;

        let handle = unsafe { OwnedFileDescriptor::from_raw_handle(handle.0) };
        Ok((handle, encoded_name))
    }

    fn build_context(
        &self,
        handle: OwnedFileDescriptor,
        full_path: PathBuf,
        is_directory: bool,
    ) -> anyhow::Result<LiteContext> {
        if is_directory {
            let ctx = LiteDirContext {
                dir: handle,
                full_path,
                name_translator: self.root_dir.name_translator.clone(),
                long_name_table: Mutex::new(None),
            };
            Ok(LiteContext::Dir(ctx))
        } else {
            let ctx = LiteRegularFileContext {
                file_like_stream: Mutex::new(self.factory.wrap(handle)?),
                full_path,
            };
            Ok(LiteContext::File(ctx))
        }
    }
}

impl LiteWinFspCore {
    pub fn fill_volume_params(&self, params: &mut VolumeParams) -> anyhow::Result<()> {
        let fs_attr = volume::get_attr(HANDLE(self.root_dir.dir.as_raw_handle()))?;
        let fs_size = volume::get_size(HANDLE(self.root_dir.dir.as_raw_handle()))?;
        params
            .sector_size(fs_size.BytesPerSector as _)
            .sectors_per_allocation_unit(fs_size.SectorsPerAllocationUnit as _)
            .max_component_length(
                self.root_dir
                    .name_translator
                    .max_virtual_path_component_size(
                        unsafe { fs_attr.as_ref() }
                            .MaximumComponentNameLength
                            .try_into()?,
                    )
                    .try_into()?,
            )
            .case_preserved_names(true)
            .case_sensitive_search(true)
            .persistent_acls(true)
            .post_disposition_only_when_necessary(true)
            .unicode_on_disk(true);

        Ok(())
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

        let mut common = |h: HANDLE| {
            let attributes = get_file_attributes(h)?;

            // cache file_attributes for Open
            unsafe {
                self.with_operation_response(|rsp| {
                    rsp.Rsp.Create.Opened.FileInfo.FileAttributes = attributes;
                })
                .unwrap();
            }

            let mut sz_security_descriptor: u32 = 0;

            if let Some(ref mut security_descriptor) = security_descriptor {
                unsafe {
                    NtQuerySecurityObject(
                        h,
                        (OWNER_SECURITY_INFORMATION
                            | GROUP_SECURITY_INFORMATION
                            | DACL_SECURITY_INFORMATION)
                            .0,
                        Some(PSECURITY_DESCRIPTOR(security_descriptor.as_mut_ptr())),
                        security_descriptor.len().try_into()?,
                        &raw mut sz_security_descriptor,
                    )
                }
                .assert_ok()
                .context("NtQuerySecurityObject")?;
            }

            Ok(FileSecurity {
                reparse: false,
                sz_security_descriptor: sz_security_descriptor.try_into()?,
                attributes,
            })
        };

        if file_name.is_empty() || file_name == u16cstr!("\\") || file_name == u16cstr!("/") {
            common(HANDLE(self.root_dir.dir.as_raw_handle()))
        } else {
            let (handle, _) = self.nt_create_file(
                file_name,
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                Default::default(),
                FILE_OPEN,
                Default::default(),
                PSECURITY_DESCRIPTOR(std::ptr::null_mut()),
            )?;
            common(HANDLE(handle.as_raw_handle()))
        }
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

        let (handle, encoded_name) = self.nt_create_file(
            file_name,
            granted_access | SYNCHRONIZE | FILE_GENERIC_READ,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT,
            PSECURITY_DESCRIPTOR(std::ptr::null_mut()),
        )?;

        let full_path = self
            .root_dir
            .full_path
            .join(Path::new(encoded_name.as_str()));

        let result = self.build_context(handle, full_path, is_directory)?;
        *file_info.as_mut() = result.get_file_info()?;

        Ok(result)
    }

    fn close(&self, context: Self::FileContext) {
        drop(context)
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: winfsp_sys::FILE_ACCESS_RIGHTS,
        file_attributes: winfsp_sys::FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: Option<&[c_void]>,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> anyhow::Result<Self::FileContext> {
        if extra_buffer.is_some() {
            return Err(NtError {
                status: STATUS_NOT_CAPABLE,
            })
            .context("extra buffer not currently supported in securefs");
        }
        let is_directory = create_options & FILE_DIRECTORY_FILE.0 != 0;
        let create_options = NTCREATEFILE_CREATE_OPTIONS(create_options)
            & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE);

        let allocation_size = if allocation_size != 0 {
            Some(self.factory.compute_max_physical_size(allocation_size))
        } else {
            None
        };

        let security_descriptor = PSECURITY_DESCRIPTOR(
            security_descriptor.map_or(std::ptr::null_mut(), |c| c.as_ptr().cast_mut()),
        );

        let (handle, encoded_name) = self.nt_create_file(
            file_name,
            FILE_ACCESS_RIGHTS(granted_access) | SYNCHRONIZE | FILE_GENERIC_READ,
            FILE_FLAGS_AND_ATTRIBUTES(file_attributes),
            FILE_CREATE,
            FILE_OPEN_REPARSE_POINT | create_options,
            security_descriptor,
        )?;

        let full_path = self
            .root_dir
            .full_path
            .join(Path::new(encoded_name.as_str()));

        let result = self.build_context(handle, full_path, is_directory)?;
        *file_info.as_mut() = result.get_file_info()?;
        Ok(result)
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> anyhow::Result<u32> {
        let LiteContext::File(context) = context else {
            return Err(NtError {
                status: STATUS_FILE_IS_A_DIRECTORY,
            })?;
        };
        let read_len = context.with_source_lock(|stream| stream.read(buffer, offset))?;
        Ok(read_len.try_into()?)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        mut buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> anyhow::Result<u32> {
        let LiteContext::File(context) = context else {
            return Err(NtError {
                status: STATUS_FILE_IS_A_DIRECTORY,
            })?;
        };
        context.with_source_lock(|stream| {
            if constrained_io {
                let size = stream.size()?;
                if offset >= size {
                    return Ok(0);
                }
                if offset + u64::try_from(buffer.len())? > size {
                    buffer = &buffer[0..(size - offset).try_into()?];
                }
            }
            stream.write(buffer, offset)?;
            *file_info = stream.as_win_handle().get_file_info()?;
            file_info.file_size = stream.size()?;
            Ok(buffer.len().try_into()?)
        })
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> anyhow::Result<()> {
        *file_info = context.get_file_info()?;
        Ok(())
    }

    fn get_volume_info(
        &self,
        out_volume_info: &mut winfsp::filesystem::VolumeInfo,
    ) -> anyhow::Result<()> {
        let fs_size = volume::get_size(HANDLE(self.root_dir.dir.as_raw_handle()))?;
        out_volume_info.free_size = u64::try_from(fs_size.AvailableAllocationUnits)?
            * u64::try_from(fs_size.BytesPerSector)?
            * u64::try_from(fs_size.SectorsPerAllocationUnit)?;
        out_volume_info.total_size = u64::try_from(fs_size.TotalAllocationUnits)?
            * u64::try_from(fs_size.BytesPerSector)?
            * u64::try_from(fs_size.SectorsPerAllocationUnit)?;
        Ok(())
    }
}

impl LiteWinFspCore {
    pub fn new(
        root_dir: &str,
        name_translator: Arc<dyn NameTranslator>,
        factory: Box<dyn IoWrapperFactory>,
    ) -> anyhow::Result<Self> {
        let handle = unsafe {
            let mut ntfilename: UNICODE_STRING = std::mem::zeroed();
            RtlDosPathNameToNtPathName_U_WithStatus(
                PWSTR::from_raw(U16CString::from_str(root_dir)?.as_mut_ptr()),
                &raw mut ntfilename,
                None,
                None,
            )
            .assert_ok()
            .context("RtlDosPathNameToNtPathName_U_WithStatus")?;
            let ntfilename = scopeguard::guard(ntfilename, |mut n| {
                RtlFreeUnicodeString(&raw mut n);
            });

            let obj_attr = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>().try_into()?,
                RootDirectory: HANDLE::default(),
                ObjectName: &raw const *ntfilename,
                Attributes: OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: std::ptr::null(),
                SecurityQualityOfService: std::ptr::null(),
            };
            let mut iosb: IO_STATUS_BLOCK = std::mem::zeroed();
            let mut h = HANDLE::default();
            NtCreateFile(
                &mut h,
                FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_LIST_DIRECTORY | FILE_TRAVERSE,
                &raw const obj_attr,
                &raw mut iosb,
                None,
                FILE_ATTRIBUTE_DIRECTORY,
                FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
                None,
                0,
            )
            .assert_ok()
            .context("NtCreateFile")?;
            OwnedFileDescriptor::from_raw_handle(h.0)
        };

        let root_dir = LiteDirContext {
            dir: handle,
            full_path: std::fs::canonicalize(Path::new(root_dir))?,
            name_translator: name_translator,
            long_name_table: Default::default(),
        };
        let core = LiteWinFspCore { root_dir, factory };

        Ok(core)
    }
}

mod volume {
    use anyhow::Context;
    use std::ffi::c_void;
    use std::mem::MaybeUninit;
    use windows::Wdk::Storage::FileSystem::{
        FILE_FS_ATTRIBUTE_INFORMATION, FileFsAttributeInformation, FileFsSizeInformation,
        NtQueryVolumeInformationFile,
    };
    use windows::Wdk::System::SystemServices::FILE_FS_SIZE_INFORMATION;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::IO_STATUS_BLOCK;
    use winfsp::constants::MAX_PATH;
    use winfsp::util::VariableSizedBox;

    use crate::AssertOk;

    pub fn get_attr(
        handle: HANDLE,
    ) -> anyhow::Result<VariableSizedBox<FILE_FS_ATTRIBUTE_INFORMATION>> {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
        let mut info = VariableSizedBox::<FILE_FS_ATTRIBUTE_INFORMATION>::new(
            MAX_PATH * std::mem::size_of::<u16>(),
        );

        unsafe {
            NtQueryVolumeInformationFile(
                handle,
                iosb.as_mut_ptr(),
                info.as_mut_ptr() as *mut _,
                info.len() as u32,
                FileFsAttributeInformation,
            )
            .assert_ok()
            .context("NtQueryVolumeInformationFile")?;
        }
        Ok(info)
    }

    pub fn get_size(handle: HANDLE) -> anyhow::Result<FILE_FS_SIZE_INFORMATION> {
        let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
        let mut info: FILE_FS_SIZE_INFORMATION = unsafe { std::mem::zeroed() };

        unsafe {
            NtQueryVolumeInformationFile(
                handle,
                iosb.as_mut_ptr(),
                (&mut info) as *mut _ as *mut c_void,
                std::mem::size_of::<FILE_FS_SIZE_INFORMATION>() as u32,
                FileFsSizeInformation,
            )
            .assert_ok()
            .context("NtQueryVolumeInformationFile")?;
        };

        Ok(info)
    }
}

pub fn mount(data: InternalMountData) -> anyhow::Result<()> {
    let core = LiteWinFspCore::new(
        &data.data_dir,
        create_name_translator(data.decrypted_params.lite_format_params())?,
        Box::new(LiteAesGcmCryptStreamFactory::new_from_params(
            &data.decrypted_params,
            !data.mount_options.disable_verification,
        )?),
    )?;
    let mut volume_params = VolumeParams::new();
    volume_params
        .file_info_timeout(
            u32::try_from(data.mount_options.attr_cache_seconds.unwrap_or(30))? * 1000u32,
        )
        .read_only_volume(data.mount_options.read_only);
    core.fill_volume_params(&mut volume_params)?;

    let start_data = Arc::new(Mutex::new(Some((core, volume_params))));

    let init = winfsp_init_or_die();
    let fsp = FileSystemServiceBuilder::new()
        .with_start(|| {
            let (core, volume_params) = start_data
                .lock()
                .take()
                .ok_or(FspError::NTSTATUS(STATUS_INVALID_PARAMETER.0))?;
            let mut host = FileSystemHost::new(volume_params, TracedWinFspWrapper::from(core))?;
            if data.mount_options.mount_point.eq_ignore_ascii_case("nul") {
                host.mount(MountPoint::NextFreeDrive)?;
            } else {
                host.mount(data.mount_options.mount_point.as_str())?;
            }
            host.start_with_threads(32)?;
            Ok(host)
        })
        .with_stop(|h| {
            if let Some(h) = h {
                h.stop();
            }
            Ok(())
        })
        .build("securefs", init)?;

    fsp.start().join().expect("thread join should succeed")?;
    Ok(())
}
