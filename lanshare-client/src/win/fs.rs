//! LanShare 文件系统 — WinFsp FileSystemContext 实现
//!
//! 将远程 LanShare 共享映射为本地盘符，支持：
//! - 浏览目录结构、读取文件内容、查看文件属性
//! - 创建/写入/删除/重命名文件与目录（需服务端授予 readwrite 权限）
//!
//! 写入模型（写回缓存）：LSP3 写入为「整文件上传」语义，而 WinFsp 是随机写。
//! 故以「写回缓存」桥接：以写方式打开文件时将远端内容下载到内存缓冲，
//! 随机写/改大小均在缓冲上进行，句柄 cleanup 时将整个缓冲上传回服务端。
//! 适用于 LAN 场景的中小文件；超大文件写入会占用相应内存。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use widestring::U16CStr;
use windows::Win32::Foundation::{
    STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_END_OF_FILE,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL};
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo,
    WideNameInfo,
};

use lanshare_client::lsp_client::{DirEntry, LspShareClient, StatResp};

// ── Win32 常量（create_options / granted_access / cleanup flags）──
/// create_options：目标为目录
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
/// granted_access：写数据
const FILE_WRITE_DATA: u32 = 0x0002;
/// granted_access：追加数据
const FILE_APPEND_DATA: u32 = 0x0004;
/// cleanup flags：本次 cleanup 需完成删除
const FSP_CLEANUP_DELETE: u32 = 0x01;

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
    /// 写回缓冲（仅以写方式打开的文件句柄为 Some）：随机写在内存进行，cleanup 时整文件上传。
    /// 其存在与否即代表本句柄是否可写。
    write_buf: Option<Arc<Mutex<WriteBuf>>>,
    /// 删除标记：set_delete(true) 后置位，cleanup 时真正删除
    delete_on_close: Arc<std::sync::atomic::AtomicBool>,
    /// 是否持有服务端文件锁（写打开时获取 exclusive lock，cleanup 时释放）
    holds_lock: bool,
}

/// 写回缓冲：内存中的文件内容 + 脏标记
#[derive(Debug)]
struct WriteBuf {
    data: Vec<u8>,
    dirty: bool,
}

/// 目录缓存条目
struct DirCacheEntry {
    entries: Vec<DirEntry>,
    cached_at: u64,
}

/// 文件缓存条目（带 LRU 访问时间戳）
struct FileCacheEntry {
    data: Vec<u8>,
    last_access: std::sync::atomic::AtomicU64,
}

/// LanShare 文件系统上下文
pub struct LanShareFs {
    client: Arc<LspShareClient>,
    /// 卷是否可写（服务端授予任一写类权限）。只读时拒绝一切写操作，卷以只读挂载。
    writable: bool,
    /// 目录缓存：路径 → 条目列表（TTL 5 秒）
    dir_cache: RwLock<HashMap<String, DirCacheEntry>>,
    /// 文件内容缓存：路径 → 数据（LRU 淘汰）
    file_cache: RwLock<HashMap<String, FileCacheEntry>>,
    /// 下一个 index_number
    next_index: std::sync::atomic::AtomicU64,
    /// 缓存访问序号（用于 LRU）
    cache_seq: std::sync::atomic::AtomicU64,
    /// 正在进行的写回上传计数（优雅退出时等待归零）
    pending_writes: Arc<AtomicUsize>,
}

const DIR_CACHE_TTL_SECS: u64 = 5;
/// 文件缓存总容量上限（64 MB）
const FILE_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;
/// 单个文件超过此大小则不缓存（16 MB），避免大文件撑爆内存
const FILE_CACHE_MAX_FILE: usize = 16 * 1024 * 1024;
/// 写回缓冲单文件上限（512 MB）：超过此大小的文件以只读方式打开，
/// 防止内存耗尽（OOM）。用户需通过 Web 端或分块工具上传超大文件。
const MAX_WRITE_BUF_SIZE: u64 = 512 * 1024 * 1024;

impl LanShareFs {
    pub fn new(client: Arc<LspShareClient>) -> Self {
        let writable = client.is_writable();
        Self {
            client,
            writable,
            dir_cache: RwLock::new(HashMap::new()),
            file_cache: RwLock::new(HashMap::new()),
            next_index: std::sync::atomic::AtomicU64::new(1),
            cache_seq: std::sync::atomic::AtomicU64::new(0),
            pending_writes: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// 获取 pending_writes 计数器的 Arc 引用（供外部监控）
    pub fn pending_writes_handle(&self) -> Arc<AtomicUsize> {
        self.pending_writes.clone()
    }

    fn next_index_number(&self) -> u64 {
        self.next_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn next_cache_seq(&self) -> u64 {
        self.cache_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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
            FILE_ATTRIBUTE_NORMAL.0
        };
        FileInfo {
            file_attributes: attrs,
            reparse_tag: 0,
            allocation_size: if stat.is_dir {
                0
            } else {
                stat.size.div_ceil(512) * 512
            },
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

        // 更新缓存（顺便清理过期条目，防止只增不减）
        {
            let mut cache = self.dir_cache.write();
            cache.retain(|_, e| now - e.cached_at < DIR_CACHE_TTL_SECS);
            cache.insert(
                path.to_string(),
                DirCacheEntry {
                    entries: entries.clone(),
                    cached_at: now,
                },
            );
        }

        Ok(entries)
    }

    /// 带缓存的文件下载（整文件缓存 + LRU 淘汰；超大文件不缓存）
    fn read_file_cached(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, String> {
        // 先检查缓存（命中时更新 LRU 时间戳）
        {
            let cache = self.file_cache.read();
            if let Some(entry) = cache.get(path) {
                entry
                    .last_access
                    .store(self.next_cache_seq(), std::sync::atomic::Ordering::Relaxed);
                if (offset as usize) < entry.data.len() {
                    let end = ((offset as usize) + len).min(entry.data.len());
                    return Ok(entry.data[offset as usize..end].to_vec());
                }
            }
        }

        // 下载整个文件（从 offset 0 开始，简化实现）
        let data = self.client.download(path, 0)?;

        // 只缓存不超过单文件上限的，避免大文件撑爆内存
        if data.len() <= FILE_CACHE_MAX_FILE {
            let mut cache = self.file_cache.write();
            // LRU 淘汰：总容量超限时移除最久未访问的条目
            let mut total: usize = cache.values().map(|e| e.data.len()).sum();
            while total + data.len() > FILE_CACHE_MAX_BYTES && !cache.is_empty() {
                let oldest = cache
                    .iter()
                    .min_by_key(|(_, e)| e.last_access.load(std::sync::atomic::Ordering::Relaxed))
                    .map(|(k, _)| k.clone());
                match oldest {
                    Some(key) => {
                        if let Some(removed) = cache.remove(&key) {
                            total -= removed.data.len();
                        }
                    }
                    None => break,
                }
            }
            cache.insert(
                path.to_string(),
                FileCacheEntry {
                    data: data.clone(),
                    last_access: std::sync::atomic::AtomicU64::new(self.next_cache_seq()),
                },
            );
        }

        if (offset as usize) < data.len() {
            let end = ((offset as usize) + len).min(data.len());
            Ok(data[offset as usize..end].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    /// 构建默认安全描述符（所有人可读可写可删除）
    fn default_security_descriptor() -> Vec<u8> {
        // SDDL: 所有人可读可写可删除（0x1201FF = FILE_GENERIC_READ|WRITE|DELETE|READ_CONTROL|SYNCHRONIZE）。
        // 写权限的实际门控由服务端会话权限 + 本卷 writable 标志负责，此处仅放开本地 ACL 限制。
        // 使用 Win32 API 转换
        use windows::core::PCWSTR;
        use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};

        let sddl = "O:BAG:BAD:P(A;;0x1201FF;;;WD)";
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
        let bytes = unsafe { std::slice::from_raw_parts(descriptor.0 as *const u8, len) }.to_vec();

        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(Some(
                windows::Win32::Foundation::HLOCAL(descriptor.0),
            ));
        }

        bytes
    }

    /// 取路径的父目录（"/a/b.txt" → "/a"；"/a" → "/"）
    fn parent_dir(path: &str) -> &str {
        let trimmed = path.trim_end_matches('/');
        match trimmed.rfind('/') {
            Some(0) => "/",
            Some(i) => &trimmed[..i],
            None => "/",
        }
    }

    /// 使指定目录的缓存失效
    fn invalidate_dir(&self, path: &str) {
        self.dir_cache.write().remove(path);
    }

    /// 使指定路径所在父目录的缓存失效
    fn invalidate_dir_parent(&self, path: &str) {
        let parent = Self::parent_dir(path).to_string();
        self.dir_cache.write().remove(&parent);
    }

    /// 使指定文件的缓存失效
    fn invalidate_file(&self, path: &str) {
        self.file_cache.write().remove(path);
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
            self.client
                .stat(&path)
                .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0))?
        };

        let attributes = if stat.is_dir {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else if stat.exists {
            FILE_ATTRIBUTE_NORMAL.0
        } else if self.writable {
            // 文件不存在但卷可写：返回普通文件属性，允许后续 create/overwrite
            FILE_ATTRIBUTE_NORMAL.0
        } else {
            return Err(winfsp::FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0));
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
        granted_access: u32,
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
            self.client
                .stat(&path)
                .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0))?
        };

        if !stat.exists {
            return Err(winfsp::FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0));
        }

        let fi = self.stat_to_fileinfo(&stat);
        *file_info.as_mut() = fi;

        // 以写方式打开文件（卷可写 + 非目录 + granted_access 含写权限）时，
        // 下载远端内容到写回缓冲，随机写在内存进行，cleanup 时整文件上传。
        // 大文件保护：超过 MAX_WRITE_BUF_SIZE 的文件以只读方式打开，防止 OOM。
        let can_write = self.client.can("write")
            && !stat.is_dir
            && (granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0
            && stat.size <= MAX_WRITE_BUF_SIZE;
        if self.client.can("write")
            && !stat.is_dir
            && (granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0
            && stat.size > MAX_WRITE_BUF_SIZE
        {
            crate::discovery::log(&format!(
                "大文件保护：{} ({} MB) 超过写回上限，以只读打开",
                path,
                stat.size / 1024 / 1024
            ));
        }
        let write_buf = if can_write {
            let data = self
                .client
                .download(&path, 0)
                .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;
            Some(Arc::new(Mutex::new(WriteBuf { data, dirty: false })))
        } else {
            None
        };

        // 写打开时尝试获取服务端文件锁（多客户端冲突协调）
        // 锁失败不阻止打开（服务端 write_req 会再次检查），仅记录日志
        let holds_lock = if write_buf.is_some() {
            match self.client.lock_file(&path, "exclusive", 60) {
                Ok(_) => true,
                Err(e) => {
                    crate::discovery::log(&format!("文件锁获取失败({}): {}", path, e));
                    false
                }
            }
        } else {
            false
        };

        Ok(LanShareHandle {
            path,
            is_dir: stat.is_dir,
            size: stat.size,
            mtime: parse_mtime(&stat.mtime),
            write_buf,
            delete_on_close: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            holds_lock,
        })
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[std::ffi::c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = Self::to_wsp_path(file_name);

        // 创建目录（需 mkdir 权限）
        if create_options & FILE_DIRECTORY_FILE != 0 {
            if !self.client.can("mkdir") {
                return Err(winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0));
            }
            self.client
                .mkdir(&path)
                .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;
            self.invalidate_dir_parent(&path);

            let now = now_filetime();
            let fi = file_info.as_mut();
            fi.file_attributes = FILE_ATTRIBUTE_DIRECTORY.0;
            fi.allocation_size = 0;
            fi.file_size = 0;
            fi.creation_time = now;
            fi.last_access_time = now;
            fi.last_write_time = now;
            fi.change_time = now;
            fi.index_number = self.next_index_number();

            return Ok(LanShareHandle {
                path,
                is_dir: true,
                size: 0,
                mtime: now,
                write_buf: None,
                delete_on_close: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                holds_lock: false,
            });
        }

        // 创建文件（需 write 权限）：建立空的脏写回缓冲，cleanup 时上传
        if !self.client.can("write") {
            return Err(winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0));
        }
        let now = now_filetime();
        let fi = file_info.as_mut();
        fi.file_attributes = FILE_ATTRIBUTE_NORMAL.0;
        fi.allocation_size = 0;
        fi.file_size = 0;
        fi.creation_time = now;
        fi.last_access_time = now;
        fi.last_write_time = now;
        fi.change_time = now;
        fi.index_number = self.next_index_number();

        Ok(LanShareHandle {
            path,
            is_dir: false,
            size: 0,
            mtime: now,
            write_buf: Some(Arc::new(Mutex::new(WriteBuf {
                data: Vec::new(),
                dirty: true,
            }))),
            delete_on_close: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            holds_lock: false,
        })
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if !self.client.can("write") {
            return Err(winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0));
        }
        if let Some(ref wb) = context.write_buf {
            let mut buf = wb.lock();
            buf.data.clear();
            buf.dirty = true;
        }
        let now = now_filetime();
        file_info.file_attributes = FILE_ATTRIBUTE_NORMAL.0;
        file_info.allocation_size = 0;
        file_info.file_size = 0;
        file_info.last_write_time = now;
        file_info.change_time = now;
        Ok(())
    }

    fn close(&self, _context: Self::FileContext) {
        // 无需清理
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // 有写回缓冲时以缓冲长度为准（写入后大小已变化）
        let size = if let Some(ref wb) = context.write_buf {
            wb.lock().data.len() as u64
        } else {
            context.size
        };
        let attrs = if context.is_dir {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_NORMAL.0
        };
        file_info.file_attributes = attrs;
        file_info.allocation_size = if context.is_dir {
            0
        } else {
            size.div_ceil(512) * 512
        };
        file_info.file_size = size;
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

        // 有写回缓冲时从缓冲读（含尚未上传的最新写入）
        if let Some(ref wb) = context.write_buf {
            let buf = wb.lock();
            if (offset as usize) >= buf.data.len() {
                return Err(winfsp::FspError::NTSTATUS(STATUS_END_OF_FILE.0));
            }
            let end = ((offset as usize) + buffer.len()).min(buf.data.len());
            let len = end - offset as usize;
            buffer[..len].copy_from_slice(&buf.data[offset as usize..end]);
            return Ok(len as u32);
        }

        if offset >= context.size {
            return Err(winfsp::FspError::NTSTATUS(STATUS_END_OF_FILE.0));
        }

        let data = self
            .read_file_cached(&context.path, offset, buffer.len())
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

        let entries = self
            .list_dir_cached(&context.path)
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
            dir_info
                .set_name_raw([b'.' as u16].as_slice())
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
            dir_info
                .set_name_raw([b'.' as u16, b'.' as u16].as_slice())
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
                entries
                    .iter()
                    .position(|e| &e.name == name)
                    .map(|i| i + 1)
                    .unwrap_or(0)
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
                FILE_ATTRIBUTE_NORMAL.0
            };
            fi.allocation_size = if entry.is_dir {
                0
            } else {
                entry.size.div_ceil(512) * 512
            };
            fi.file_size = entry.size;
            fi.creation_time = mtime;
            fi.last_access_time = mtime;
            fi.last_write_time = mtime;
            fi.change_time = mtime;
            fi.index_number = self.next_index_number();

            let name_wide: Vec<u16> = entry.name.encode_utf16().collect();
            dir_info
                .set_name_raw(name_wide.as_slice())
                .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;

            if !dir_info.append_to_buffer(buffer, &mut cursor) {
                return Ok(cursor);
            }
        }

        DirInfo::<255>::finalize_buffer(buffer, &mut cursor);
        Ok(cursor)
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
        let wb = context
            .write_buf
            .as_ref()
            .ok_or(winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;
        let mut buf = wb.lock();

        // 确定写入偏移：write_to_eof 表示追加到末尾
        let off = if write_to_eof {
            buf.data.len() as u64
        } else {
            offset
        };

        // constrained_io：不得超出当前文件长度（缓存 IO）
        let data = if constrained_io {
            let cur_len = buf.data.len() as u64;
            if off >= cur_len {
                return Ok(0);
            }
            let max = (cur_len - off) as usize;
            &buffer[..buffer.len().min(max)]
        } else {
            buffer
        };

        let end = off as usize + data.len();
        if end > buf.data.len() {
            buf.data.resize(end, 0);
        }
        buf.data[off as usize..end].copy_from_slice(data);
        buf.dirty = true;

        let now = now_filetime();
        let new_size = buf.data.len() as u64;
        file_info.file_size = new_size;
        file_info.allocation_size = new_size.div_ceil(512) * 512;
        file_info.last_write_time = now;
        file_info.change_time = now;

        Ok(data.len() as u32)
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let wb = context
            .write_buf
            .as_ref()
            .ok_or(winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;
        if set_allocation_size {
            // 仅调整分配大小，不改动数据
            file_info.allocation_size = new_size;
        } else {
            let mut buf = wb.lock();
            buf.data.resize(new_size as usize, 0);
            buf.dirty = true;
            file_info.file_size = new_size;
            file_info.allocation_size = new_size.div_ceil(512) * 512;
            let now = now_filetime();
            file_info.last_write_time = now;
            file_info.change_time = now;
        }
        Ok(())
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        if !self.client.can("delete") {
            return Err(winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0));
        }
        if !delete_file {
            // 取消删除标记
            context
                .delete_on_close
                .store(false, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
        // 目录非空时拒绝删除
        if context.is_dir {
            let entries = self
                .client
                .list_dir(&context.path)
                .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;
            if !entries.is_empty() {
                return Err(winfsp::FspError::NTSTATUS(STATUS_DIRECTORY_NOT_EMPTY.0));
            }
        }
        // 仅置标记，真正删除在 cleanup（FspCleanupDelete）时执行
        context
            .delete_on_close
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        if !self.client.can("rename") {
            return Err(winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0));
        }
        let new_path = Self::to_wsp_path(new_file_name);
        let old_path = context.path.clone();
        self.client
            .rename(&old_path, &new_path)
            .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;
        // 失效新旧两个父目录的缓存
        self.invalidate_dir_parent(&old_path);
        self.invalidate_dir_parent(&new_path);
        Ok(())
    }

    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
        // 删除：set_delete(true) 或 FILE_DELETE_ON_CLOSE 触发
        if flags & FSP_CLEANUP_DELETE != 0
            || context
                .delete_on_close
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            let _ = self.client.delete(&context.path, context.is_dir);
            if context.is_dir {
                self.invalidate_dir(&context.path);
            } else {
                self.invalidate_file(&context.path);
            }
            self.invalidate_dir_parent(&context.path);
            return;
        }

        // 写回：脏缓冲整文件上传（追踪 pending 计数，供优雅退出等待）
        if let Some(ref wb) = context.write_buf {
            let mut buf = wb.lock();
            if buf.dirty {
                self.pending_writes.fetch_add(1, Ordering::AcqRel);
                let result = self.client.upload_data(&context.path, &buf.data);
                self.pending_writes.fetch_sub(1, Ordering::AcqRel);
                if result.is_ok() {
                    buf.dirty = false;
                    self.invalidate_file(&context.path);
                    self.invalidate_dir_parent(&context.path);
                    crate::discovery::log(&format!("写回完成: {}", context.path));
                } else {
                    crate::discovery::log(&format!(
                        "写回失败: {} - {:?}",
                        context.path,
                        result.err()
                    ));
                }
            }
        }

        // 释放服务端文件锁
        if context.holds_lock {
            let _ = self.client.unlock_file(&context.path);
        }
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        out_volume_info.total_size = 1024 * 1024 * 1024 * 1024; // 1 TB 虚拟
        out_volume_info.free_size = 512 * 1024 * 1024 * 1024; // 512 GB 虚拟
        out_volume_info.set_volume_label(std::ffi::OsString::from("LanShare"));
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
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // 文件 flush：脏写回缓冲立即上传
        if let Some(ctx) = context {
            if let Some(ref wb) = ctx.write_buf {
                let mut buf = wb.lock();
                if buf.dirty {
                    self.client
                        .upload_data(&ctx.path, &buf.data)
                        .map_err(|_| winfsp::FspError::NTSTATUS(STATUS_ACCESS_DENIED.0))?;
                    buf.dirty = false;
                    let now = now_filetime();
                    let size = buf.data.len() as u64;
                    file_info.file_size = size;
                    file_info.allocation_size = size.div_ceil(512) * 512;
                    file_info.last_write_time = now;
                    file_info.change_time = now;
                }
            }
        }
        Ok(())
    }
}
