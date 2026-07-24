//! Dokan 0.7.4 FFI bindings
#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ffi::{OsStr, OsString};
use std::ptr;
use std::mem;

pub const DOKAN_VERSION: u16 = 740;
pub const DOKAN_OPTION_KEEP_ALIVE: u32 = 8;
pub const DOKAN_OPTION_REMOVABLE: u32 = 32;

#[repr(C)]
pub struct DOKAN_OPTIONS {
    pub version: u16,
    pub thread_count: u16,
    pub options: u32,
    pub global_context: u64,
    pub mount_point: *const u16,
}

#[repr(C)]
pub struct DOKAN_FILE_INFO {
    pub context: u64,
    pub dokan_context: u64,
    pub dokan_options: *const DOKAN_OPTIONS,
    pub process_id: u32,
    pub is_directory: u8,
    pub delete_on_close: u8,
    pub paging_io: u8,
    pub synchronous_io: u8,
    pub nocache: u8,
    pub write_to_end_of_file: u8,
}

// Windows types
pub type BOOL = i32;
pub type DWORD = u32;
pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;
pub type LPVOID = *mut std::ffi::c_void;
pub type LPCVOID = *const std::ffi::c_void;
pub type LPDWORD = *mut DWORD;
pub type PULONG = *mut ULONG;
pub type LONGLONG = i64;
pub type ULONG = u32;
pub type USHORT = u16;
pub type PULONGLONG = *mut u64;
pub type ULONG64 = u64;
pub type HANDLE = *mut std::ffi::c_void;
pub type SECURITY_INFORMATION = u32;
pub type PSECURITY_INFORMATION = *mut SECURITY_INFORMATION;
pub type PSECURITY_DESCRIPTOR = LPVOID;

#[repr(C)]
pub struct FILETIME {
    pub dw_low_date_time: u32,
    pub dw_high_date_time: u32,
}

#[repr(C)]
pub struct BY_HANDLE_FILE_INFORMATION {
    pub dw_file_attributes: DWORD,
    pub ft_creation_time: FILETIME,
    pub ft_last_access_time: FILETIME,
    pub ft_last_write_time: FILETIME,
    pub dw_volume_serial_number: DWORD,
    pub n_file_size_high: DWORD,
    pub n_file_size_low: DWORD,
    pub n_number_of_links: DWORD,
    pub n_file_index_high: DWORD,
    pub n_file_index_low: DWORD,
}

#[repr(C)]
pub struct WIN32_FIND_DATAW {
    pub dw_file_attributes: DWORD,
    pub ft_creation_time: FILETIME,
    pub ft_last_access_time: FILETIME,
    pub ft_last_write_time: FILETIME,
    pub n_file_size_high: DWORD,
    pub n_file_size_low: DWORD,
    pub dw_reserved0: DWORD,
    pub dw_reserved1: DWORD,
    pub c_file_name: [u16; 260],
    pub c_alternate_name: [u16; 14],
}

pub const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x10;
pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;
pub const FILE_CASE_SENSITIVE_SEARCH: DWORD = 1;
pub const FILE_UNICODE_ON_DISK: DWORD = 4;

pub const CREATE_NEW: DWORD = 1;
pub const CREATE_ALWAYS: DWORD = 2;
pub const OPEN_EXISTING: DWORD = 3;
pub const OPEN_ALWAYS: DWORD = 4;

pub type PFillFindData = unsafe extern "system" fn(*const WIN32_FIND_DATAW, *mut DOKAN_FILE_INFO) -> i32;

// Callback types
pub type FnCreateFile = unsafe extern "system" fn(LPCWSTR, DWORD, DWORD, DWORD, DWORD, *mut DOKAN_FILE_INFO) -> i32;
pub type FnOpenDirectory = unsafe extern "system" fn(LPCWSTR, *mut DOKAN_FILE_INFO) -> i32;
pub type FnCreateDirectory = unsafe extern "system" fn(LPCWSTR, *mut DOKAN_FILE_INFO) -> i32;
pub type FnCleanup = unsafe extern "system" fn(LPCWSTR, *mut DOKAN_FILE_INFO) -> i32;
pub type FnCloseFile = unsafe extern "system" fn(LPCWSTR, *mut DOKAN_FILE_INFO) -> i32;
pub type FnReadFile = unsafe extern "system" fn(LPCWSTR, LPVOID, DWORD, LPDWORD, LONGLONG, *mut DOKAN_FILE_INFO) -> i32;
pub type FnWriteFile = unsafe extern "system" fn(LPCWSTR, LPCVOID, DWORD, LPDWORD, LONGLONG, *mut DOKAN_FILE_INFO) -> i32;
pub type FnFlushFileBuffers = unsafe extern "system" fn(LPCWSTR, *mut DOKAN_FILE_INFO) -> i32;
pub type FnGetFileInformation = unsafe extern "system" fn(LPCWSTR, *mut BY_HANDLE_FILE_INFORMATION, *mut DOKAN_FILE_INFO) -> i32;
pub type FnFindFiles = unsafe extern "system" fn(LPCWSTR, PFillFindData, *mut DOKAN_FILE_INFO) -> i32;
pub type FnFindFilesWithPattern = unsafe extern "system" fn(LPCWSTR, LPCWSTR, PFillFindData, *mut DOKAN_FILE_INFO) -> i32;
pub type FnSetFileAttributes = unsafe extern "system" fn(LPCWSTR, DWORD, *mut DOKAN_FILE_INFO) -> i32;
pub type FnSetFileTime = unsafe extern "system" fn(LPCWSTR, *const FILETIME, *const FILETIME, *const FILETIME, *mut DOKAN_FILE_INFO) -> i32;
pub type FnDeleteFile = unsafe extern "system" fn(LPCWSTR, *mut DOKAN_FILE_INFO) -> i32;
pub type FnDeleteDirectory = unsafe extern "system" fn(LPCWSTR, *mut DOKAN_FILE_INFO) -> i32;
pub type FnMoveFile = unsafe extern "system" fn(LPCWSTR, LPCWSTR, BOOL, *mut DOKAN_FILE_INFO) -> i32;
pub type FnSetEndOfFile = unsafe extern "system" fn(LPCWSTR, LONGLONG, *mut DOKAN_FILE_INFO) -> i32;
pub type FnSetAllocationSize = unsafe extern "system" fn(LPCWSTR, LONGLONG, *mut DOKAN_FILE_INFO) -> i32;
pub type FnLockFile = unsafe extern "system" fn(LPCWSTR, LONGLONG, LONGLONG, *mut DOKAN_FILE_INFO) -> i32;
pub type FnUnlockFile = unsafe extern "system" fn(LPCWSTR, LONGLONG, LONGLONG, *mut DOKAN_FILE_INFO) -> i32;
pub type FnGetDiskFreeSpace = unsafe extern "system" fn(PULONGLONG, PULONGLONG, PULONGLONG, *mut DOKAN_FILE_INFO) -> i32;
pub type FnGetVolumeInformation = unsafe extern "system" fn(LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD, *mut DOKAN_FILE_INFO) -> i32;
pub type FnUnmount = unsafe extern "system" fn(*mut DOKAN_FILE_INFO) -> i32;
pub type FnGetFileSecurity = unsafe extern "system" fn(LPCWSTR, PSECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG, *mut DOKAN_FILE_INFO) -> i32;
pub type FnSetFileSecurity = unsafe extern "system" fn(LPCWSTR, PSECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, *mut DOKAN_FILE_INFO) -> i32;

#[repr(C)]
pub struct DOKAN_OPERATIONS {
    pub create_file: FnCreateFile,
    pub open_directory: FnOpenDirectory,
    pub create_directory: FnCreateDirectory,
    pub cleanup: FnCleanup,
    pub close_file: FnCloseFile,
    pub read_file: FnReadFile,
    pub write_file: FnWriteFile,
    pub flush_file_buffers: FnFlushFileBuffers,
    pub get_file_information: FnGetFileInformation,
    pub find_files: FnFindFiles,
    pub find_files_with_pattern: FnFindFilesWithPattern,
    pub set_file_attributes: FnSetFileAttributes,
    pub set_file_time: FnSetFileTime,
    pub delete_file: FnDeleteFile,
    pub delete_directory: FnDeleteDirectory,
    pub move_file: FnMoveFile,
    pub set_end_of_file: FnSetEndOfFile,
    pub set_allocation_size: FnSetAllocationSize,
    pub lock_file: FnLockFile,
    pub unlock_file: FnUnlockFile,
    pub get_disk_free_space: FnGetDiskFreeSpace,
    pub get_volume_information: FnGetVolumeInformation,
    pub unmount: FnUnmount,
    pub get_file_security: FnGetFileSecurity,
    pub set_file_security: FnSetFileSecurity,
}

// Dokan API
#[link(name = "dokan")]
extern "system" {
    pub fn DokanMain(options: *const DOKAN_OPTIONS, operations: *const DOKAN_OPERATIONS) -> i32;
    pub fn DokanUnmount(drive_letter: u16) -> BOOL;
    pub fn DokanRemoveMountPoint(mount_point: LPCWSTR) -> BOOL;
    pub fn DokanVersion() -> ULONG;
    pub fn DokanResetTimeout(timeout: ULONG, file_info: *mut DOKAN_FILE_INFO) -> BOOL;
}

// Error codes
pub const DOKAN_SUCCESS: i32 = 0;
pub const DOKAN_ERROR: i32 = -1;
pub const DOKAN_DRIVE_LETTER_ERROR: i32 = -2;
pub const DOKAN_DRIVER_INSTALL_ERROR: i32 = -3;
pub const DOKAN_START_ERROR: i32 = -4;
pub const DOKAN_MOUNT_ERROR: i32 = -5;
pub const DOKAN_MOUNT_POINT_ERROR: i32 = -6;

// Windows error codes
pub const ERROR_FILE_NOT_FOUND: i32 = 2;
pub const ERROR_PATH_NOT_FOUND: i32 = 3;
pub const ERROR_ACCESS_DENIED: i32 = 5;
pub const ERROR_READ_FAULT: i32 = 30;
pub const ERROR_WRITE_FAULT: i32 = 29;
pub const ERROR_INTERNAL_ERROR: i32 = 1359;
pub const ERROR_CALL_NOT_IMPLEMENTED: i32 = 120;

// Helper functions
pub fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

pub fn from_wide(w: LPCWSTR) -> String {
    if w.is_null() { return String::new(); }
    let mut len = 0;
    unsafe {
        while *w.offset(len) != 0 { len += 1; }
        let slice = std::slice::from_raw_parts(w, len as usize);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}
