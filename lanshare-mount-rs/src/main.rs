//! LanShare Dokan Mount Client (Rust)
//! 
//! Mounts LanShare server as a Windows drive letter using Dokan 0.7.4

mod dokan_ffi;

use std::sync::Arc;
use parking_lot::Mutex;
use lanshare_client::wsp_client::WspClient;
use dokan_ffi::*;

struct MountState {
    client: Arc<WspClient>,
}

impl MountState {
    fn new(client: Arc<WspClient>) -> Self {
        Self { client }
    }
}

// Global state
static mut STATE: Option<Arc<MountState>> = None;

fn get_state() -> &'static Arc<MountState> {
    unsafe { STATE.as_ref().unwrap() }
}

fn path_to_unix(wpath: LPCWSTR) -> String {
    let s = from_wide(wpath);
    s.replace('\\', "/")
}

// Dokan callbacks
unsafe extern "system" fn mount_create_file(
    file_name: LPCWSTR,
    access_mode: DWORD,
    share_mode: DWORD,
    creation_disposition: DWORD,
    flags_and_attributes: DWORD,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    let path = path_to_unix(file_name);
    let state = get_state();
    
    // Check if file/dir exists
    match state.client.stat(&path) {
        Ok(stat) => {
            (*file_info).is_directory = if stat.is_dir { 1 } else { 0 };
            0
        }
        Err(_) => {
            // File doesn't exist
            if creation_disposition == CREATE_NEW || creation_disposition == CREATE_ALWAYS {
                // Create new file
                match state.client.upload_start(&path, 0) {
                    Ok(_) => {
                        (*file_info).is_directory = 0;
                        0
                    }
                    Err(_) => -ERROR_ACCESS_DENIED
                }
            } else {
                -ERROR_FILE_NOT_FOUND
            }
        }
    }
}

unsafe extern "system" fn mount_open_directory(
    file_name: LPCWSTR,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    let path = path_to_unix(file_name);
    if path.is_empty() || path == "/" {
        (*file_info).is_directory = 1;
        return 0;
    }
    
    let state = get_state();
    match state.client.stat(&path) {
        Ok(stat) if stat.is_dir => {
            (*file_info).is_directory = 1;
            0
        }
        _ => -ERROR_PATH_NOT_FOUND
    }
}

unsafe extern "system" fn mount_create_directory(
    file_name: LPCWSTR,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    let path = path_to_unix(file_name);
    let state = get_state();
    
    match state.client.mkdir(&path) {
        Ok(_) => 0,
        Err(_) => -ERROR_ACCESS_DENIED
    }
}

unsafe extern "system" fn mount_cleanup(
    file_name: LPCWSTR,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    0
}

unsafe extern "system" fn mount_close_file(
    file_name: LPCWSTR,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    0
}

unsafe extern "system" fn mount_read_file(
    file_name: LPCWSTR,
    buffer: LPVOID,
    size: DWORD,
    read_size: LPDWORD,
    offset: LONGLONG,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    let path = path_to_unix(file_name);
    let state = get_state();
    
    // Download file from offset
    let mut total = 0u32;
    let buf_slice = std::slice::from_raw_parts_mut(buffer as *mut u8, size as usize);
    
    // Use download API
    match state.client.download(&path, offset) {
        Ok(data) => {
            let copy_len = std::cmp::min(data.len(), size as usize);
            buf_slice[..copy_len].copy_from_slice(&data[..copy_len]);
            *read_size = copy_len as DWORD;
            0
        }
        Err(_) => -ERROR_READ_FAULT
    }
}

unsafe extern "system" fn mount_write_file(
    file_name: LPCWSTR,
    buffer: LPCVOID,
    size: DWORD,
    write_size: LPDWORD,
    offset: LONGLONG,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    let path = path_to_unix(file_name);
    let state = get_state();
    
    let buf_slice = std::slice::from_raw_parts(buffer as *const u8, size as usize);
    
    match state.client.upload_data(&path, offset, buf_slice) {
        Ok(_) => {
            *write_size = size;
            0
        }
        Err(_) => -ERROR_WRITE_FAULT
    }
}

unsafe extern "system" fn mount_flush_file_buffers(
    file_name: LPCWSTR,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    0
}

unsafe extern "system" fn mount_get_file_information(
    file_name: LPCWSTR,
    info: *mut BY_HANDLE_FILE_INFORMATION,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    let path = path_to_unix(file_name);
    let state = get_state();
    
    match state.client.stat(&path) {
        Ok(stat) => {
            (*info).dw_file_attributes = if stat.is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
            (*info).n_file_size_low = stat.size as DWORD;
            (*info).n_file_size_high = (stat.size >> 32) as DWORD;
            
            // Parse mtime (unix timestamp)
            if let Ok(mtime) = stat.mtime.parse::<i64>() {
                if mtime > 0 {
                    // Convert unix timestamp to Windows FILETIME
                    let wt = mtime * 10_000_000 + 116_444_736_000_000_000;
                    (*info).ft_last_write_time.dw_low_date_time = wt as DWORD;
                    (*info).ft_last_write_time.dw_high_date_time = (wt >> 32) as DWORD;
                    (*info).ft_last_access_time = (*info).ft_last_write_time;
                    (*info).ft_creation_time = (*info).ft_last_write_time;
                }
            }
            0
        }
        Err(_) => -ERROR_FILE_NOT_FOUND
    }
}

unsafe extern "system" fn mount_find_files(
    file_name: LPCWSTR,
    fill_find_data: PFillFindData,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    let path = path_to_unix(file_name);
    let state = get_state();
    
    match state.client.list_dir(&path) {
        Ok(entries) => {
            for entry in entries {
                let mut wfd: WIN32_FIND_DATAW = std::mem::zeroed();
                wfd.dw_file_attributes = if entry.is_dir {
                    FILE_ATTRIBUTE_DIRECTORY
                } else {
                    FILE_ATTRIBUTE_NORMAL
                };
                wfd.n_file_size_low = entry.size as DWORD;
                wfd.n_file_size_high = (entry.size >> 32) as DWORD;
                
                // Convert name to wide string
                let name_wide: Vec<u16> = entry.name.encode_utf16().collect();
                let copy_len = std::cmp::min(name_wide.len(), 259);
                wfd.c_file_name[..copy_len].copy_from_slice(&name_wide[..copy_len]);
                wfd.c_file_name[copy_len] = 0;
                
                // Parse mtime
                if let Ok(mtime) = entry.mtime.parse::<i64>() {
                    if mtime > 0 {
                        let wt = mtime * 10_000_000 + 116_444_736_000_000_000;
                        wfd.ft_last_write_time.dw_low_date_time = wt as DWORD;
                        wfd.ft_last_write_time.dw_high_date_time = (wt >> 32) as DWORD;
                        wfd.ft_last_access_time = wfd.ft_last_write_time;
                        wfd.ft_creation_time = wfd.ft_last_write_time;
                    }
                }
                
                fill_find_data(&wfd, file_info);
            }
            0
        }
        Err(_) => -ERROR_PATH_NOT_FOUND
    }
}

unsafe extern "system" fn mount_delete_file(
    file_name: LPCWSTR,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    let path = path_to_unix(file_name);
    let state = get_state();
    
    match state.client.delete_file(&path) {
        Ok(_) => 0,
        Err(_) => -ERROR_ACCESS_DENIED
    }
}

unsafe extern "system" fn mount_delete_directory(
    file_name: LPCWSTR,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    mount_delete_file(file_name, file_info)
}

unsafe extern "system" fn mount_move_file(
    old_name: LPCWSTR,
    new_name: LPCWSTR,
    replace_existing: BOOL,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    let old_path = path_to_unix(old_name);
    let new_path = path_to_unix(new_name);
    let state = get_state();
    
    match state.client.rename(&old_path, &new_path) {
        Ok(_) => 0,
        Err(_) => -ERROR_ACCESS_DENIED
    }
}

unsafe extern "system" fn mount_set_end_of_file(
    file_name: LPCWSTR,
    length: LONGLONG,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    0
}

unsafe extern "system" fn mount_set_allocation_size(
    file_name: LPCWSTR,
    length: LONGLONG,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    0
}

unsafe extern "system" fn mount_lock_file(
    file_name: LPCWSTR,
    offset: LONGLONG,
    length: LONGLONG,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    0
}

unsafe extern "system" fn mount_unlock_file(
    file_name: LPCWSTR,
    offset: LONGLONG,
    length: LONGLONG,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    0
}

unsafe extern "system" fn mount_set_file_attributes(
    file_name: LPCWSTR,
    attributes: DWORD,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    0
}

unsafe extern "system" fn mount_set_file_time(
    file_name: LPCWSTR,
    creation: *const FILETIME,
    access: *const FILETIME,
    write: *const FILETIME,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    0
}

unsafe extern "system" fn mount_get_disk_free_space(
    free_bytes_available: PULONGLONG,
    total_number_of_bytes: PULONGLONG,
    total_number_of_free_bytes: PULONGLONG,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    *free_bytes_available = 10 * 1024 * 1024 * 1024; // 10 GB
    *total_number_of_bytes = 100 * 1024 * 1024 * 1024; // 100 GB
    *total_number_of_free_bytes = 100 * 1024 * 1024 * 1024;
    0
}

unsafe extern "system" fn mount_get_volume_information(
    volume_name_buffer: LPWSTR,
    volume_name_size: DWORD,
    volume_serial_number: LPDWORD,
    max_component_length: LPDWORD,
    flags: LPDWORD,
    file_system_name_buffer: LPWSTR,
    file_system_name_size: DWORD,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    // Copy "LanShare" to volume name
    let name = "LanShare";
    let name_wide: Vec<u16> = name.encode_utf16().collect();
    let copy_len = std::cmp::min(name_wide.len(), (volume_name_size - 1) as usize);
    std::ptr::copy_nonoverlapping(name_wide.as_ptr(), volume_name_buffer, copy_len);
    *volume_name_buffer.offset(copy_len as isize) = 0;
    
    *volume_serial_number = 0x12345678;
    *max_component_length = 255;
    *flags = FILE_CASE_SENSITIVE_SEARCH | FILE_UNICODE_ON_DISK;
    
    // Copy "WSP-FS" to file system name
    let fs_name = "WSP-FS";
    let fs_wide: Vec<u16> = fs_name.encode_utf16().collect();
    let copy_len = std::cmp::min(fs_wide.len(), (file_system_name_size - 1) as usize);
    std::ptr::copy_nonoverlapping(fs_wide.as_ptr(), file_system_name_buffer, copy_len);
    *file_system_name_buffer.offset(copy_len as isize) = 0;
    
    0
}

unsafe extern "system" fn mount_unmount(
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    println!("File system unmounted");
    0
}

unsafe extern "system" fn mount_get_file_security(
    file_name: LPCWSTR,
    security_information: PSECURITY_INFORMATION,
    security_descriptor: PSECURITY_DESCRIPTOR,
    length: ULONG,
    length_needed: PULONG,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    -ERROR_CALL_NOT_IMPLEMENTED
}

unsafe extern "system" fn mount_set_file_security(
    file_name: LPCWSTR,
    security_information: PSECURITY_INFORMATION,
    security_descriptor: PSECURITY_DESCRIPTOR,
    length: ULONG,
    file_info: *mut DOKAN_FILE_INFO,
) -> i32 {
    -ERROR_CALL_NOT_IMPLEMENTED
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 4 {
        eprintln!("LanShare Dokan Mount Client (Rust) v1.0");
        eprintln!();
        eprintln!("Usage: lanshare-mount-rs <server:port> <pin> <drive_letter>");
        eprintln!();
        eprintln!("Requires Dokan 0.7.4+ installed");
        eprintln!();
        eprintln!("Example: lanshare-mount-rs 192.168.0.100:8080 123456 M");
        std::process::exit(1);
    }
    
    let server = &args[1];
    let pin = &args[2];
    let drive = args[3].chars().next().unwrap_or('L');
    
    // Parse server address
    let (host, port) = if let Some(colon_pos) = server.rfind(':') {
        let h = &server[..colon_pos];
        let p = server[colon_pos + 1..].parse::<u16>().unwrap_or(8080);
        (h.to_string(), p)
    } else {
        (server.clone(), 8080)
    };
    
    println!("Dokan version: {}", unsafe { DokanVersion() });
    println!("Connecting to {}:{} ...", host, port);

    // Single-instance guard: refuse to start if another copy is already mounted
    // on this drive letter. Uses a PID file in %TEMP% so a crashed process
    // doesn't permanently block the drive.
    let lock_path = std::env::temp_dir().join(format!("lanshare-mount-{}.lock", drive));
    if lock_path.exists() {
        if let Ok(pid_str) = std::fs::read_to_string(&lock_path) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                // Is that PID still alive?
                let still_alive = std::path::Path::new(&format!("C:\\Windows\\Temp\\lanshare-{}.alive", pid)).exists();
                if still_alive {
                    eprintln!(
                        "Another Lanshare mount instance is already running on {}: (PID {}).\n\
                         Use that one, or kill it first.",
                        drive, pid
                    );
                    std::process::exit(1);
                } else {
                    println!("Removing stale lock file from previous run (PID {}).", pid);
                    let _ = std::fs::remove_file(&lock_path);
                }
            }
        }
    }
    let _ = std::fs::write(&lock_path, std::process::id().to_string());
    // Heartbeat file the lock checker reads
    let heartbeat = std::path::Path::new(&format!("C:\\Windows\\Temp\\lanshare-{}.alive", std::process::id()));
    let _ = std::fs::write(heartbeat, b"1");
    let hb_path_str = heartbeat.to_string_lossy().into_owned();

    // If a previous mapping is still around on the same drive letter, try to
    // unmount it first so DokanMain doesn't fail with -5 (ERROR_ALREADY_ASSIGNED).
    {
        let mount_point = format!("{}:\\", drive);
        let mount_wide: Vec<u16> = mount_point.encode_utf16().chain(std::iter::once(0)).collect();
        let removed = unsafe { DokanRemoveMountPoint(mount_wide.as_ptr()) };
        if removed != 0 {
            println!("Removed stale mount on {}:", drive);
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    // If a previous mapping is still around on the same drive letter, try to
    // unmount it first so DokanMain doesn't fail with -5 (ERROR_ALREADY_ASSIGNED).
    {
        let mount_point = format!("{}:\\", drive);
        let mount_wide: Vec<u16> = mount_point.encode_utf16().chain(std::iter::once(0)).collect();
        let removed = unsafe { DokanRemoveMountPoint(mount_wide.as_ptr()) };
        if removed != 0 {
            println!("Removed stale mount on {}:", drive);
            // Give Dokan a moment to actually release the device
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    // Create WSP client
    let client = Arc::new(WspClient::new(&format!("{}:{}", host, port), pin));
    
    // Connect and authenticate
    if let Err(e) = client.connect() {
        eprintln!("Connection failed: {}", e);
        std::process::exit(1);
    }
    
    println!("Authenticated. Mounting as {}: ...", drive);
    
    // Initialize global state
    let state = Arc::new(MountState::new(client));
    unsafe {
        STATE = Some(state);
    }
    
    // Setup Dokan options
    let mount_point = format!("{}:", drive);
    let mount_wide: Vec<u16> = mount_point.encode_utf16().chain(std::iter::once(0)).collect();
    
    let options = DOKAN_OPTIONS {
        version: DOKAN_VERSION,
        thread_count: 2,
        options: DOKAN_OPTION_KEEP_ALIVE | DOKAN_OPTION_REMOVABLE,
        global_context: 0,
        mount_point: mount_wide.as_ptr(),
    };
    
    let operations = DOKAN_OPERATIONS {
        create_file: mount_create_file,
        open_directory: mount_open_directory,
        create_directory: mount_create_directory,
        cleanup: mount_cleanup,
        close_file: mount_close_file,
        read_file: mount_read_file,
        write_file: mount_write_file,
        flush_file_buffers: mount_flush_file_buffers,
        get_file_information: mount_get_file_information,
        find_files: mount_find_files,
        find_files_with_pattern: std::mem::transmute(std::ptr::null::<fn()>()),
        set_file_attributes: mount_set_file_attributes,
        set_file_time: mount_set_file_time,
        delete_file: mount_delete_file,
        delete_directory: mount_delete_directory,
        move_file: mount_move_file,
        set_end_of_file: mount_set_end_of_file,
        set_allocation_size: mount_set_allocation_size,
        lock_file: mount_lock_file,
        unlock_file: mount_unlock_file,
        get_disk_free_space: mount_get_disk_free_space,
        get_volume_information: mount_get_volume_information,
        unmount: mount_unmount,
        get_file_security: mount_get_file_security,
        set_file_security: mount_set_file_security,
    };
    
    let status = unsafe { DokanMain(&options, &operations) };

    // Clean up PID lock + heartbeat on exit
    let _ = std::fs::remove_file(&lock_path);
    let _ = std::fs::remove_file(&hb_path_str);

    if status == -5 {
        eprintln!(
            "Mount failed: drive {}: is already in use by another application or a \
             stale Dokan mount. Try a different drive letter.",
            drive
        );
    } else if status != 0 && status != -4 {
        eprintln!("Dokan exited with status {}", status);
    } else {
        println!("Dokan exited cleanly with status {}", status);
    }
}
