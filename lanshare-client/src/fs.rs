//! LanShare 只读文件系统 — WinFsp FileSystemContext 实现
//!
//! 将远程 LanShare 共享映射为本地盘符，支持：
//! - 浏览目录结构
//! - 读取文件内容
//! - 查看文件属性（大小、修改时间）
//!
//! 不支持（只读）：创建、写入、删除、重命名

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use widestring::U16CStr;
use windows::Win32::Foundation::{
    STATUS_ACCESS_DENIED, STATUS_END_OF_FILE, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
};
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo,
    WideNameInfo,
};

use crate::wsp_client::{DirEntry, StatResp, WspClient};

/// 将 Unix 时间戳（秒）转为 Windows FILETIME（100ns since 1601）
fn unix_to_filetime(secs: u64) -> u64 {
    secs * 10_000_000 + 116_444_736_000_000_000
}

/// 解析 mtime 字符串为 FILETIME
fn parse_mtime(mtime: &str) -> u64 {
    let secs: u64 = mtime.parse().unwrap_or(0);
    unix_to_filetime(secs)
}

/// 当前时间的 FILETIME
fn now_filetime() -> u64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_to_filetime(secs)
}

/// 文件句柄 — 记录打开的文件路径和元信息
#[derive(Clone, Debug)]
pub struct LanShareHandle {
    /// 远程路径（WSP 格式，如 "/docs/readme.txt"）
    path: String,
    is_dir: bool,
    size: u64,
    mtime: u64,
}

/// 目录缓存条目
struct DirCacheEntry {
    entries: Vec<DirEntry>,
    cached_at: u64,
}

/// LanShare 只读文件系统上下文
pub struct LanShareFs {
    client: Arc<WspClient>,
    /// 目录缓存：路径 → 条目列表（TTL 5 秒）
    dir_cache: RwLock<HashMap<String, DirCacheEntry>>,
    /// 文件内容缓存：路径 → (offset, data)
    file_cache: RwLock<HashMap<String, Vec<u8>>>,
    /// 下一个 index_number
    next_index: std::sync::atomic::AtomicU64,
}

const DIR_CACHE_TTL_SECS: u64 = 5;

impl LanShareFs {
    pub fn new(client: Arc<WspClient>) -> Self {
        Self {
            client,
            dir_cache: RwLock::new(HashMap::new()),
            file_cache: RwLock::new(HashMap::new()),
            next_index: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn next_index_number(&self) -> u64 {
        self.next_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// 将 WinFsp 路径（U16CStr，反斜杠分隔）转为 WSP 路径（正斜杠）
    fn to_wsp_path(file_name: &U16CStr) -> String {
        let wide: Vec<u16> = file_name.as_slice().to_vec();
        let s = String::from_utf16_lossy(&wide);
        // WinFsp 路径如 "\docs\readme.txt" → WSP 路径 "/docs/readme.txt"
        s.replace('\\', "/")
    }

    /// 从 StatResp 构建 FileInfo
    fn stat_to_fileinfo(&self, stat: &StatResp) -> FileInfo {
        let mtime = parse_mtime(&stat.mtime);
        let attrs = if stat.is_dir {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_READONLY.0 | FILE_ATTRIBUTE_NORMAL.0
        };
        FileInfo {
            file_attributes: attrs,
            reparse_tag: 0,
            allocation_size: if stat.is_dir { 0 } else { (stat.size + 511) / 512 * 512 },
            file_size: stat.size,
            creation_time: mtime,
            last_access_time: mtime,
            last_write_time: mtime,
            change_time: mtime,
            index_number: self.next_index_number(),
            hard_links: 0,
            ea_size: 0,
        }
    }

    /// 带缓存的列目录
    fn list_dir_cached(&self, path: &str) -> Result<Vec<DirEntry>, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 检查缓存
        {
            let cache = self.dir_cache.read();
            if let Some(entry) = cache.get(path) {
                if now - entry.cached_at < DIR_CACHE_TTL_SECS {
                    return Ok(entry.entries.clone());
                }
            }
        }

        // 远程获取
        let entries = self.client.list_dir(path)?;

        // 更新缓存
        {
            let mut cache = self.dir_cache.write();
            cache.insert(path.to_string(), DirCacheEntry {
                entries: entries.clone(),
                cached_at: now,
            });
        }

        Ok(entries)
    }

    /// 带缓存的文件下载（整文件缓存，适合小文件；大文件按需读取）
    fn read_file_cached(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, String> {
        // 先检查缓存
        {
            let cache = self.file_cache.read();
            if let Some(data) = cache.get(path) {
                if (offset as usize) < data.len() {
                    let end = ((offset as usize) + len).min(data.len());
                    return Ok(data[offset as usize..end].to_vec());
                }
            }
        }

        // 下载整个文件（从 offset 0 开始，简化实现）
        let data = self.client.download(path, 0)?;

        // 缓存
        {
            let mut cache = self.file_cache.write();
            // 限制缓存大小：最多缓存 100 个文件
            if cache.len() >= 100 {
                cache.clear();
            }
            cache.insert(path.to_string(), data.clone());
        }

        if (offset as usize) < data.len() {
            let end = ((offset as usize) + len).min(data.len());
            Ok(data[offset as usize..end].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    /// 构建默认安全描述符（所有人只读）
    fn default_security_descriptor() -> Vec<u8> {
        // SDDL: O:BAG:BAD:P(A;;FR;;;WD) — 所有人只读
        // 使用 Win32 API 转换
        use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};
        use windows::core::PCWSTR;

        let sddl = "O:BAG:BAD:P(A;;FR;;;WD)";
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut size = 0u32;

        unsafe {
            let _ = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                1, // SDDL_REVISION_1
                &mut descriptor,
                Some(&mut size),
            );
        }

        if descriptor.0.is_null() {
            return Vec::new();
        }

        let len = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
        let bytes = unsafe {
            std::slice::from_raw_parts(descriptor.0 as *const u8, len)
        }.to_vec();

        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(
                Some(windows::Win32::Foundation::HLOCAL(descriptor.0)),
            );
        }

        bytes
    }
}

impl FileSystemContext for LanShareFs {
    type FileContext = LanShareHandle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [std::ffi::c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let path = Self::to_wsp_path(file_name);

        // 根目录特殊处理
        let stat = if path == "/" || path.is_empty() {
            StatResp {
                name: String::new(),
                is_dir: true,
                size: 0,
                mtime: "0".to_string(),
                exists: true,
            }
        } else {
            self.client.stat(&path).map_err(|_| {
                winfsp::FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0)
            })?
        };

        if !stat.exists {
            return Err(winfsp::FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0));
        }

        let attributes = if stat.is_dir {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_READONLY.0
        };

        let sd = Self::default_security_descriptor();
        let sz = sd.len() as u64;

        if let Some(buffer) = security_descriptor {
            if (buffer.len() as u64) >= sz {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        sd.as_ptr(),
                        buffer.as_mut_ptr() as *mut u8,
                        sd.len(),
                    );
                }
            }
        }

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: sz,
            attributes,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = Self::to_wsp_path(file_name);

        let stat = if path == "/" || path.is_empty() {
            StatResp {
                name: String::new(),
                is_dir: true,
                size: 0,
                mtime: "0".to_string(),
                exists: true,
            }
        } else {
            self.client.stat(&path).map_err(|_| {
                winfsp::FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0)
            })?
        };

        if !stat.exists {
            return Err(winfsp::FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0));
        }

        let fi = self.stat_to_fileinfo(&stat);
        *file_info.as_mut() = fi;

        Ok(LanShareHandle {
            path,
            is_dir: stat.is_dir,
            size: stat.size,
            mtime: parse_mtime(&stat.mtime),
        })
    }

    fn close(&self, _context: Self::FileContext) {
        // 无需清理
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let attrs = if context.is_dir {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_READONLY.0 | FILE_ATTRIBUTE_NORMAL.0
        };
        file_info.file_attributes = attrs;
        file_info.allocation_size = if context.is_dir { 0 } else { (context.size + 511) / 512 * 512 };
        file_info.file_size = context.size;
        file_info.creation_time = context.mtime;
        file_info.last_access_time = context.mtime;
        file_info.last_write_time = context.mtime;
        file_info.change_time = context.mtime;
        file_info.index_number = self.next_index_number();
        Ok(())
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        if context.is_dir {
            return Err(winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0));
        }
        if offset >= context.size {
            return Err(winfsp::FspError::NTSTATUS(STATUS_END_OF_FILE.0));
        }

        let data = self.read_file_cached(&context.path, offset, buffer.len())
            .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;

        let len = data.len().min(buffer.len());
        buffer[..len].copy_from_slice(&data[..len]);
        Ok(len as u32)
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if !context.is_dir {
            return Err(winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0));
        }

        let entries = self.list_dir_cached(&context.path)
            .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_OBJECT_PATH_NOT_FOUND.0))?;

        let mut cursor = 0u32;
        let mut dir_info: DirInfo<255> = DirInfo::new();

        // 处理 "." 和 ".."
        let marker_is_none = marker.is_none();
        let marker_is_dot = marker
            .inner_as_cstr()
            .map(|m| m.as_slice() == [b'.' as u16])
            .unwrap_or(false);

        if marker_is_none {
            dir_info.reset();
            let fi = dir_info.file_info_mut();
            fi.file_attributes = FILE_ATTRIBUTE_DIRECTORY.0;
            fi.creation_time = now_filetime();
            fi.last_access_time = fi.creation_time;
            fi.last_write_time = fi.creation_time;
            fi.change_time = fi.creation_time;
            dir_info.set_name_raw([b'.' as u16].as_slice())
                .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;
            if !dir_info.append_to_buffer(buffer, &mut cursor) {
                return Ok(cursor);
            }
        }

        if marker_is_none || marker_is_dot {
            dir_info.reset();
            let fi = dir_info.file_info_mut();
            fi.file_attributes = FILE_ATTRIBUTE_DIRECTORY.0;
            fi.creation_time = now_filetime();
            fi.last_access_time = fi.creation_time;
            fi.last_write_time = fi.creation_time;
            fi.change_time = fi.creation_time;
            dir_info.set_name_raw([b'.' as u16, b'.' as u16].as_slice())
                .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;
            if !dir_info.append_to_buffer(buffer, &mut cursor) {
                return Ok(cursor);
            }
        }

        // 确定起始位置（marker 之后的条目）
        let marker_name: Option<String> = marker
            .inner_as_cstr()
            .map(|m| String::from_utf16_lossy(m.as_slice()));

        let start_idx = if let Some(ref name) = marker_name {
            if name == "." || name == ".." {
                0
            } else {
                entries.iter().position(|e| &e.name == name).map(|i| i + 1).unwrap_or(0)
            }
        } else {
            0
        };

        for entry in entries.iter().skip(start_idx) {
            dir_info.reset();
            let fi = dir_info.file_info_mut();
            let mtime = parse_mtime(&entry.mtime);
            fi.file_attributes = if entry.is_dir {
                FILE_ATTRIBUTE_DIRECTORY.0
            } else {
                FILE_ATTRIBUTE_READONLY.0 | FILE_ATTRIBUTE_NORMAL.0
            };
            fi.allocation_size = if entry.is_dir { 0 } else { (entry.size + 511) / 512 * 512 };
            fi.file_size = entry.size;
            fi.creation_time = mtime;
            fi.last_access_time = mtime;
            fi.last_write_time = mtime;
            fi.change_time = mtime;
            fi.index_number = self.next_index_number();

            let name_wide: Vec<u16> = entry.name.encode_utf16().collect();
            dir_info.set_name_raw(name_wide.as_slice())
                .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;

            if !dir_info.append_to_buffer(buffer, &mut cursor) {
                return Ok(cursor);
            }
        }

        DirInfo::<255>::finalize_buffer(buffer, &mut cursor);
        Ok(cursor)
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        out_volume_info.total_size = 1024 * 1024 * 1024 * 1024; // 1 TB 虚拟
        out_volume_info.free_size = 512 * 1024 * 1024 * 1024; // 512 GB 虚拟
        out_volume_info.set_volume_label(&std::ffi::OsString::from("LanShare"));
        Ok(())
    }

    fn get_security(
        &self,
        _context: &Self::FileContext,
        security_descriptor: Option<&mut [std::ffi::c_void]>,
    ) -> winfsp::Result<u64> {
        let sd = Self::default_security_descriptor();
        let sz = sd.len() as u64;
        if let Some(buffer) = security_descriptor {
            if (buffer.len() as u64) >= sz {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        sd.as_ptr(),
                        buffer.as_mut_ptr() as *mut u8,
                        sd.len(),
                    );
                }
            }
        }
        Ok(sz)
    }

    fn flush(
        &self,
        _context: Option<&Self::FileContext>,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        Ok(()) // 只读，无需 flush
    }
}
