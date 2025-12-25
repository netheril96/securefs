#![cfg(windows)]
use anyhow::Result;
use std::ffi::c_void;
use std::fmt::Debug;
use tracing::{Level, span};
use windows::Win32::Foundation::{
    STATUS_INVALID_DEVICE_REQUEST, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    STATUS_UNSUCCESSFUL,
};
use winfsp::U16CStr;
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, ModificationDescriptor, OpenFileInfo, VolumeInfo,
};

use winfsp_sys::{
    FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES, FSP_FSCTL_TRANSACT_REQ, FSP_FSCTL_TRANSACT_RSP,
};

use crate::win::NtError;

pub trait WinFspFileSystemCore: Sized {
    type FileContext: Sized + Debug;

    /// Get security information and attributes for a file or directory by its
    /// file name.
    ///
    /// If the file system supports reparse points, `reparse_point_resolver`
    /// should be called with the input file_name. If a reparse point is
    /// found at any point in the path, the result can be immediately
    /// returned like so the following.
    ///
    /// ```rust,ignore
    /// if let Some(security) = resolve_reparse_points(file_name.as_ref()) {
    ///    Ok(security)
    /// }
    /// ```
    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> Result<FileSecurity>;

    /// Opens a file or a directory.
    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext>;

    /// Close a file or directory handle.
    fn close(&self, context: Self::FileContext);

    #[allow(clippy::too_many_arguments)]
    /// Create a new file or directory.
    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: Option<&[c_void]>,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Clean up a file.
    fn cleanup(&self, context: &Self::FileContext, file_name: Option<&U16CStr>, flags: u32) {}

    /// Flush a file or volume.
    ///
    /// If `context` is `None`, the request is to flush the entire volume.
    fn flush(&self, context: Option<&Self::FileContext>, file_info: &mut FileInfo) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Get file or directory information.
    fn get_file_info(&self, context: &Self::FileContext, file_info: &mut FileInfo) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Get file or directory security descriptor.
    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: Option<&mut [c_void]>,
    ) -> Result<u64> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Set file or directory security descriptor.
    fn set_security(
        &self,
        context: &Self::FileContext,
        security_information: u32,
        modification_descriptor: ModificationDescriptor,
    ) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Overwrite a file.
    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        replace_file_attributes: bool,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Read directory entries from a directory handle.
    fn read_directory(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Renames a file or directory.
    fn rename(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Set file or directory basic information.
    #[allow(clippy::too_many_arguments)]
    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Set the file delete flag.
    ///
    /// ## Safety
    /// The file should **never** be deleted in this function. Instead,
    /// set a flag to indicate that the file is to be deleted later by
    /// [`FileSystemContext::cleanup`](crate::filesystem::FileSystemContext::cleanup).
    fn set_delete(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        delete_file: bool,
    ) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Set the file or allocation size.
    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Read from a file. Return the number of bytes read,
    fn read(&self, context: &Self::FileContext, buffer: &mut [u8], offset: u64) -> Result<u32> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Write to a file. Return the number of bytes written.
    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> Result<u32> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Get directory information for a single file or directory within a parent
    /// directory.
    ///
    /// This method is only called when
    /// [VolumeParams::pass_query_directory_filename](crate::host::VolumeParams::pass_query_directory_filename)
    /// is set to true, and the file system was created with
    /// [FileSystemParams::use_dir_info_by_name](crate::host::FileSystemParams).
    /// set to true.
    fn get_dir_info_by_name(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        out_dir_info: &mut DirInfo,
    ) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Get information about the volume.
    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Set the volume label.
    fn set_volume_label(&self, volume_label: &U16CStr, volume_info: &mut VolumeInfo) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Get information about named streams.
    fn get_stream_info(&self, context: &Self::FileContext, buffer: &mut [u8]) -> Result<u32> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Get reparse point information by its name.
    ///
    /// In the WinFSP C API, this method is usually called manually by the
    /// interface method `ResolveReparsePoints`. winfsp-rs automatically
    /// handles resolution of reparse points if this method is implemented
    /// properly.
    fn get_reparse_point_by_name(
        &self,
        file_name: &U16CStr,
        is_directory: bool,
        buffer: &mut [u8],
    ) -> Result<u64> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Get reparse point information.
    fn get_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &mut [u8],
    ) -> Result<u64> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Set reparse point information.
    fn set_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &[u8],
    ) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Delete reparse point information.
    fn delete_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &[u8],
    ) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Get extended attribute information.
    fn get_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
    ) -> Result<u32> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Set extended attribute information.
    fn set_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        file_info: &mut FileInfo,
    ) -> Result<()> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Process a control code from the [`DeviceIoControl`](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol) API.
    fn control(
        &self,
        context: &Self::FileContext,
        control_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u32> {
        Err(NtError {
            status: STATUS_INVALID_DEVICE_REQUEST,
        })?
    }

    /// Inform the file system that its dispatcher has been stopped.
    ///
    /// If the dispatcher was stopped via the driver being unloaded, or
    /// otherwise some non-normal situation, `normally` will be false.
    ///
    /// Do not attempt to call
    /// [`FspFileSystemStopServiceIfNecessary`](winfsp_sys::FspFileSystemStopServiceIfNecessary),
    /// it will be called after this function ends. All cleanup done within
    /// this function should be user-mode only.
    fn dispatcher_stopped(&self, normally: bool) {}

    /// Get the context response of the current FSP interface operation.
    ///
    /// ## Safety
    /// This function may be used only when servicing one of the
    /// `FileSystemContext` operations. The current operation context is
    /// stored in thread local storage.
    ///
    /// ## Warning
    /// If implementing a filesystem, the default implementation should be
    /// sufficient for most if not all cases. Be careful if providing your
    /// own implementation.
    unsafe fn with_operation_response<T, F>(&self, f: F) -> Option<T>
    where
        F: FnOnce(&mut FSP_FSCTL_TRANSACT_RSP) -> T,
    {
        unsafe {
            if let Some(context) = winfsp_sys::FspFileSystemGetOperationContext().as_ref()
                && let Some(response) = context.Response.as_mut()
            {
                return Some(f(response));
            }
        }
        None
    }

    /// Get the context request of the current FSP interface operation.
    ///
    /// ## Safety
    /// This function may be used only when servicing one of the
    /// `FileSystemContext` operations. The current operation context is
    /// stored in thread local storage.
    ///
    /// ## Warning
    /// If implementing a filesystem, the default implementation should be
    /// sufficient for most if not all cases. Be careful if providing your
    /// own implementation.
    unsafe fn with_operation_request<T, F>(&self, f: F) -> Option<T>
    where
        F: FnOnce(&FSP_FSCTL_TRANSACT_REQ) -> T,
    {
        unsafe {
            if let Some(context) = winfsp_sys::FspFileSystemGetOperationContext().as_ref()
                && let Some(request) = context.Request.as_ref()
            {
                return Some(f(request));
            }
        }
        None
    }
}

pub struct TracedWinFspWrapper<T: WinFspFileSystemCore> {
    inner: T,
}

impl<T: WinFspFileSystemCore> From<T> for TracedWinFspWrapper<T> {
    fn from(value: T) -> Self {
        Self { inner: value }
    }
}

impl<T: WinFspFileSystemCore> WinFspFileSystemCore for TracedWinFspWrapper<T> {
    type FileContext = T::FileContext;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> Result<FileSecurity> {
        let _span = span!(Level::ERROR, "get_security_by_name").entered();
        match self.inner.get_security_by_name(
            file_name,
            security_descriptor,
            reparse_point_resolver,
        ) {
            Ok(ret) => {
                tracing::debug!(?file_name, ?ret);
                Ok(ret)
            }
            Err(err) => {
                if let Some(NtError { status }) = err.downcast_ref::<NtError>()
                    && (*status == STATUS_OBJECT_NAME_NOT_FOUND
                        || *status == STATUS_OBJECT_PATH_NOT_FOUND)
                {
                    // These two are frequent occurrences, and they are also quite expected.
                    tracing::debug!(?file_name, err = "File not found");
                } else {
                    tracing::warn!(?file_name, ?err);
                }
                Err(err)
            }
        }
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext> {
        let _span = span!(Level::ERROR, "open").entered();
        match self
            .inner
            .open(file_name, create_options, granted_access, file_info)
        {
            Ok(ret) => {
                tracing::debug!(
                    ?file_name,
                    create_options,
                    ?granted_access,
                    ?file_info,
                    ?ret
                );
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?file_name, create_options, ?granted_access, ?err);
                Err(err)
            }
        }
    }

    fn close(&self, context: Self::FileContext) {
        let _span = span!(Level::ERROR, "close").entered();
        self.inner.close(context);
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: Option<&[c_void]>,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext> {
        let _span = span!(Level::ERROR, "create").entered();
        match self.inner.create(
            file_name,
            create_options,
            granted_access,
            file_attributes,
            security_descriptor,
            allocation_size,
            extra_buffer,
            extra_buffer_is_reparse_point,
            file_info,
        ) {
            Ok(ret) => {
                tracing::debug!(
                    ?file_name,
                    create_options,
                    ?granted_access,
                    ?file_attributes,
                    allocation_size,
                    extra_buffer.len = extra_buffer.map(|b| b.len()),
                    extra_buffer_is_reparse_point,
                    ?file_info,
                    ?ret
                );
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(
                    ?file_name,
                    create_options,
                    ?granted_access,
                    ?file_attributes,
                    allocation_size,
                    extra_buffer.len = extra_buffer.map(|b| b.len()),
                    extra_buffer_is_reparse_point,
                    ?err
                );
                Err(err)
            }
        }
    }
    fn cleanup(&self, context: &Self::FileContext, file_name: Option<&U16CStr>, flags: u32) {
        let _span = span!(Level::ERROR, "cleanup").entered();
        self.inner.cleanup(context, file_name, flags);
        tracing::debug!(?context, ?file_name, flags);
    }

    fn flush(&self, context: Option<&Self::FileContext>, file_info: &mut FileInfo) -> Result<()> {
        let _span = span!(Level::ERROR, "flush").entered();
        match self.inner.flush(context, file_info) {
            Ok(ret) => {
                tracing::debug!(?context, ?ret, ?file_info);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, ?err);
                Err(err)
            }
        }
    }

    fn get_file_info(&self, context: &Self::FileContext, file_info: &mut FileInfo) -> Result<()> {
        let _span = span!(Level::ERROR, "get_file_info").entered();
        match self.inner.get_file_info(context, file_info) {
            Ok(ret) => {
                tracing::debug!(?context, ?ret, ?file_info);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, ?err);
                Err(err)
            }
        }
    }

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: Option<&mut [c_void]>,
    ) -> Result<u64> {
        let _span = span!(Level::ERROR, "get_security").entered();
        match self.inner.get_security(context, security_descriptor) {
            Ok(ret) => {
                tracing::debug!(?context, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, ?err);
                Err(err)
            }
        }
    }

    fn set_security(
        &self,
        context: &Self::FileContext,
        security_information: u32,
        modification_descriptor: ModificationDescriptor,
    ) -> Result<()> {
        let _span = span!(Level::ERROR, "set_security").entered();
        match self
            .inner
            .set_security(context, security_information, modification_descriptor)
        {
            Ok(ret) => {
                tracing::debug!(?context, security_information, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, security_information, ?err);
                Err(err)
            }
        }
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        replace_file_attributes: bool,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        let _span = span!(Level::ERROR, "overwrite").entered();
        match self.inner.overwrite(
            context,
            file_attributes,
            replace_file_attributes,
            allocation_size,
            extra_buffer,
            file_info,
        ) {
            Ok(ret) => {
                tracing::debug!(
                    ?context,
                    ?file_attributes,
                    replace_file_attributes,
                    allocation_size,
                    extra_buffer.len = extra_buffer.map(|b| b.len()),
                    ?ret,
                    ?file_info
                );
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(
                    ?context,
                    ?file_attributes,
                    replace_file_attributes,
                    allocation_size,
                    extra_buffer.len = extra_buffer.map(|b| b.len()),
                    ?err
                );
                Err(err)
            }
        }
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32> {
        let _span = span!(Level::ERROR, "read_directory").entered();
        match self.inner.read_directory(context, pattern, marker, buffer) {
            Ok(ret) => {
                tracing::debug!(?context, ?pattern, buffer.len = buffer.len(), ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, ?pattern, buffer.len = buffer.len(), ?err);
                Err(err)
            }
        }
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<()> {
        let _span = span!(Level::ERROR, "rename").entered();
        match self
            .inner
            .rename(context, file_name, new_file_name, replace_if_exists)
        {
            Ok(ret) => {
                tracing::debug!(
                    ?context,
                    ?file_name,
                    ?new_file_name,
                    replace_if_exists,
                    ?ret
                );
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(
                    ?context,
                    ?file_name,
                    ?new_file_name,
                    replace_if_exists,
                    ?err
                );
                Err(err)
            }
        }
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        let _span = span!(Level::ERROR, "set_basic_info").entered();
        match self.inner.set_basic_info(
            context,
            file_attributes,
            creation_time,
            last_access_time,
            last_write_time,
            last_change_time,
            file_info,
        ) {
            Ok(ret) => {
                tracing::debug!(
                    ?context,
                    file_attributes,
                    creation_time,
                    last_access_time,
                    last_write_time,
                    last_change_time,
                    ?ret,
                    ?file_info
                );
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(
                    ?context,
                    file_attributes,
                    creation_time,
                    last_access_time,
                    last_write_time,
                    last_change_time,
                    ?err
                );
                Err(err)
            }
        }
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        delete_file: bool,
    ) -> Result<()> {
        let _span = span!(Level::ERROR, "set_delete").entered();
        match self.inner.set_delete(context, file_name, delete_file) {
            Ok(ret) => {
                tracing::debug!(?context, ?file_name, delete_file, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, ?file_name, delete_file, ?err);
                Err(err)
            }
        }
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        let _span = span!(Level::ERROR, "set_file_size").entered();
        match self
            .inner
            .set_file_size(context, new_size, set_allocation_size, file_info)
        {
            Ok(ret) => {
                tracing::debug!(?context, new_size, set_allocation_size, ?ret, ?file_info);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, new_size, set_allocation_size, ?err);
                Err(err)
            }
        }
    }

    fn read(&self, context: &Self::FileContext, buffer: &mut [u8], offset: u64) -> Result<u32> {
        let _span = span!(Level::ERROR, "read").entered();
        match self.inner.read(context, buffer, offset) {
            Ok(ret) => {
                tracing::debug!(?context, offset, buffer.len = buffer.len(), ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, offset, buffer.len = buffer.len(), ?err);
                Err(err)
            }
        }
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> Result<u32> {
        let _span = span!(Level::ERROR, "write").entered();
        match self.inner.write(
            context,
            buffer,
            offset,
            write_to_eof,
            constrained_io,
            file_info,
        ) {
            Ok(ret) => {
                tracing::debug!(
                    ?context,
                    offset,
                    buffer.len = buffer.len(),
                    write_to_eof,
                    constrained_io,
                    ?ret,
                    ?file_info
                );
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(
                    ?context,
                    offset,
                    buffer.len = buffer.len(),
                    write_to_eof,
                    constrained_io,
                    ?err
                );
                Err(err)
            }
        }
    }

    fn get_dir_info_by_name(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        out_dir_info: &mut DirInfo,
    ) -> Result<()> {
        let _span = span!(Level::ERROR, "get_dir_info_by_name").entered();
        match self
            .inner
            .get_dir_info_by_name(context, file_name, out_dir_info)
        {
            Ok(ret) => {
                tracing::debug!(?context, ?file_name, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, ?file_name, ?err);
                Err(err)
            }
        }
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> Result<()> {
        let _span = span!(Level::ERROR, "get_volume_info").entered();
        match self.inner.get_volume_info(out_volume_info) {
            Ok(ret) => {
                tracing::debug!(?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?err);
                Err(err)
            }
        }
    }

    fn set_volume_label(&self, volume_label: &U16CStr, volume_info: &mut VolumeInfo) -> Result<()> {
        let _span = span!(Level::ERROR, "set_volume_label").entered();
        match self.inner.set_volume_label(volume_label, volume_info) {
            Ok(ret) => {
                tracing::debug!(?volume_label, ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?volume_label, ?err);
                Err(err)
            }
        }
    }

    fn get_stream_info(&self, context: &Self::FileContext, buffer: &mut [u8]) -> Result<u32> {
        let _span = span!(Level::ERROR, "get_stream_info").entered();
        match self.inner.get_stream_info(context, buffer) {
            Ok(ret) => {
                tracing::debug!(?context, buffer.len = buffer.len(), ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, buffer.len = buffer.len(), ?err);
                Err(err)
            }
        }
    }

    fn get_reparse_point_by_name(
        &self,
        file_name: &U16CStr,
        is_directory: bool,
        buffer: &mut [u8],
    ) -> Result<u64> {
        let _span = span!(Level::ERROR, "get_reparse_point_by_name").entered();
        match self
            .inner
            .get_reparse_point_by_name(file_name, is_directory, buffer)
        {
            Ok(ret) => {
                tracing::debug!(?file_name, is_directory, buffer.len = buffer.len(), ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?file_name, is_directory, buffer.len = buffer.len(), ?err);
                Err(err)
            }
        }
    }

    fn get_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &mut [u8],
    ) -> Result<u64> {
        let _span = span!(Level::ERROR, "get_reparse_point").entered();
        match self.inner.get_reparse_point(context, file_name, buffer) {
            Ok(ret) => {
                tracing::debug!(?context, ?file_name, buffer.len = buffer.len(), ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, ?file_name, buffer.len = buffer.len(), ?err);
                Err(err)
            }
        }
    }

    fn set_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &[u8],
    ) -> Result<()> {
        let _span = span!(Level::ERROR, "set_reparse_point").entered();
        match self.inner.set_reparse_point(context, file_name, buffer) {
            Ok(ret) => {
                tracing::debug!(?context, ?file_name, buffer.len = buffer.len(), ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, ?file_name, buffer.len = buffer.len(), ?err);
                Err(err)
            }
        }
    }

    fn delete_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &[u8],
    ) -> Result<()> {
        let _span = span!(Level::ERROR, "delete_reparse_point").entered();
        match self.inner.delete_reparse_point(context, file_name, buffer) {
            Ok(ret) => {
                tracing::debug!(?context, ?file_name, buffer.len = buffer.len(), ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, ?file_name, buffer.len = buffer.len(), ?err);
                Err(err)
            }
        }
    }

    fn get_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
    ) -> Result<u32> {
        let _span = span!(Level::ERROR, "get_extended_attributes").entered();
        match self.inner.get_extended_attributes(context, buffer) {
            Ok(ret) => {
                tracing::debug!(?context, buffer.len = buffer.len(), ?ret);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, buffer.len = buffer.len(), ?err);
                Err(err)
            }
        }
    }

    fn set_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        file_info: &mut FileInfo,
    ) -> Result<()> {
        let _span = span!(Level::ERROR, "set_extended_attributes").entered();
        match self
            .inner
            .set_extended_attributes(context, buffer, file_info)
        {
            Ok(ret) => {
                tracing::debug!(?context, buffer.len = buffer.len(), ?ret, ?file_info);
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(?context, buffer.len = buffer.len(), ?err);
                Err(err)
            }
        }
    }

    fn control(
        &self,
        context: &Self::FileContext,
        control_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u32> {
        let _span = span!(Level::ERROR, "control").entered();
        match self.inner.control(context, control_code, input, output) {
            Ok(ret) => {
                tracing::debug!(
                    ?context,
                    control_code,
                    input.len = input.len(),
                    output.len = output.len(),
                    ?ret
                );
                Ok(ret)
            }
            Err(err) => {
                tracing::warn!(
                    ?context,
                    control_code,
                    input.len = input.len(),
                    output.len = output.len(),
                    ?err
                );
                Err(err)
            }
        }
    }

    fn dispatcher_stopped(&self, normally: bool) {
        let _span = span!(Level::ERROR, "dispatcher_stopped").entered();
        self.inner.dispatcher_stopped(normally);
        tracing::debug!(normally);
    }
}

impl<T: WinFspFileSystemCore> winfsp::filesystem::FileSystemContext for TracedWinFspWrapper<T> {
    type FileContext = T::FileContext;

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: Option<&[c_void]>,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        WinFspFileSystemCore::create(
            self,
            file_name,
            create_options,
            granted_access,
            file_attributes,
            security_descriptor,
            allocation_size,
            extra_buffer,
            extra_buffer_is_reparse_point,
            file_info,
        )
        .map_err(|e| to_winfsp_error(&e))
    }

    fn cleanup(&self, context: &Self::FileContext, file_name: Option<&U16CStr>, flags: u32) {
        WinFspFileSystemCore::cleanup(self, context, file_name, flags)
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::flush(self, context, file_info).map_err(|e| to_winfsp_error(&e))
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::get_file_info(self, context, file_info)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        WinFspFileSystemCore::get_security(self, context, security_descriptor)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn set_security(
        &self,
        context: &Self::FileContext,
        security_information: u32,
        modification_descriptor: ModificationDescriptor,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::set_security(
            self,
            context,
            security_information,
            modification_descriptor,
        )
        .map_err(|e| to_winfsp_error(&e))
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        replace_file_attributes: bool,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::overwrite(
            self,
            context,
            file_attributes,
            replace_file_attributes,
            allocation_size,
            extra_buffer,
            file_info,
        )
        .map_err(|e| to_winfsp_error(&e))
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        WinFspFileSystemCore::read_directory(self, context, pattern, marker, buffer)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::rename(self, context, file_name, new_file_name, replace_if_exists)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::set_basic_info(
            self,
            context,
            file_attributes,
            creation_time,
            last_access_time,
            last_write_time,
            last_change_time,
            file_info,
        )
        .map_err(|e| to_winfsp_error(&e))
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::set_delete(self, context, file_name, delete_file)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::set_file_size(self, context, new_size, set_allocation_size, file_info)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        WinFspFileSystemCore::read(self, context, buffer, offset).map_err(|e| to_winfsp_error(&e))
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        WinFspFileSystemCore::write(
            self,
            context,
            buffer,
            offset,
            write_to_eof,
            constrained_io,
            file_info,
        )
        .map_err(|e| to_winfsp_error(&e))
    }

    fn get_dir_info_by_name(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        out_dir_info: &mut DirInfo,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::get_dir_info_by_name(self, context, file_name, out_dir_info)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        WinFspFileSystemCore::get_volume_info(self, out_volume_info)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn set_volume_label(
        &self,
        volume_label: &U16CStr,
        volume_info: &mut VolumeInfo,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::set_volume_label(self, volume_label, volume_info)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn get_stream_info(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        WinFspFileSystemCore::get_stream_info(self, context, buffer)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn get_reparse_point_by_name(
        &self,
        file_name: &U16CStr,
        is_directory: bool,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        WinFspFileSystemCore::get_reparse_point_by_name(self, file_name, is_directory, buffer)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn get_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        WinFspFileSystemCore::get_reparse_point(self, context, file_name, buffer)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn set_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &[u8],
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::set_reparse_point(self, context, file_name, buffer)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn delete_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &[u8],
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::delete_reparse_point(self, context, file_name, buffer)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn get_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        WinFspFileSystemCore::get_extended_attributes(self, context, buffer)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn set_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        WinFspFileSystemCore::set_extended_attributes(self, context, buffer, file_info)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn control(
        &self,
        context: &Self::FileContext,
        control_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> winfsp::Result<u32> {
        WinFspFileSystemCore::control(self, context, control_code, input, output)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn dispatcher_stopped(&self, normally: bool) {
        WinFspFileSystemCore::dispatcher_stopped(self, normally)
    }

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        WinFspFileSystemCore::get_security_by_name(
            self,
            file_name,
            security_descriptor,
            reparse_point_resolver,
        )
        .map_err(|e| to_winfsp_error(&e))
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        WinFspFileSystemCore::open(self, file_name, create_options, granted_access, file_info)
            .map_err(|e| to_winfsp_error(&e))
    }

    fn close(&self, context: Self::FileContext) {
        WinFspFileSystemCore::close(self, context)
    }
}

pub fn to_winfsp_error(e: &anyhow::Error) -> winfsp::FspError {
    if let Some(e) = e.downcast_ref::<NtError>() {
        return winfsp::FspError::NTSTATUS(e.status.0);
    }
    if let Some(e) = e.downcast_ref::<std::io::Error>()
        && let Some(code) = e.raw_os_error()
    {
        return winfsp::FspError::WIN32(code as _);
    }

    winfsp::FspError::NTSTATUS(STATUS_UNSUCCESSFUL.0)
}
