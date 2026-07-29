//! FUSE 文件系统实现 — 将 LSP3 远程共享映射为本地目录
//!
//! 写入模型与 Windows 版一致：写回缓存（内存整文件），flush/release 时上传。
//! 同样实现大文件保护（>512MB 拒绝写入）和文件锁。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use parking_lot::RwLock;

use lanshare_client::LspShareClient;

use crate::discovery::log;

/// 写回缓冲单文件上限（512 MB）
const MAX_WRITE_BUF_SIZE: u64 = 512 * 1024 * 1024;

/// TTL 属性缓存时间
const ATTR_TTL: Duration = Duration::from_secs(1);

const FUSE_ROOT_ID: u64 = 1;

// ── 内部数据结构 ──

struct InodeTable {
    /// inode → 远端路径
    paths: HashMap<u64, String>,
    /// 远端路径 → inode（反向索引）
    inodes: HashMap<String, u64>,
    next_ino: u64,
}

impl InodeTable {
    fn new() -> Self {
        let mut paths = HashMap::new();
        let mut inodes = HashMap::new();
        paths.insert(FUSE_ROOT_ID, "/".to_string());
        inodes.insert("/".to_string(), FUSE_ROOT_ID);
        Self {
            paths,
            inodes,
            next_ino: 2,
        }
    }

    fn path_of(&self, ino: u64) -> Option<&str> {
        self.paths.get(&ino).map(|s| s.as_str())
    }

    /// 获取或分配路径对应的 inode
    fn get_or_alloc(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.inodes.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.paths.insert(ino, path.to_string());
        self.inodes.insert(path.to_string(), ino);
        ino
    }

    /// 移除路径对应的 inode（删除/重命名时）
    fn remove_path(&mut self, path: &str) {
        if let Some(ino) = self.inodes.remove(path) {
            self.paths.remove(&ino);
        }
    }

    /// 重命名路径映射
    fn rename_path(&mut self, old: &str, new: &str) {
        if let Some(ino) = self.inodes.remove(old) {
            self.paths.insert(ino, new.to_string());
            self.inodes.insert(new.to_string(), ino);
        }
    }
}

struct OpenFile {
    path: String,
    /// 写回缓冲区（None = 只读打开）
    write_buf: Option<Vec<u8>>,
    /// 只读打开时缓存的文件内容
    read_cache: Option<Vec<u8>>,
    dirty: bool,
    holds_lock: bool,
}

/// FUSE 文件系统上下文
pub struct LanShareFuse {
    client: Arc<LspShareClient>,
    table: RwLock<InodeTable>,
    files: RwLock<HashMap<u64, OpenFile>>,
    next_fh: RwLock<u64>,
    pending_writes: Arc<AtomicUsize>,
}

impl LanShareFuse {
    pub fn new(client: Arc<LspShareClient>) -> Self {
        Self {
            client,
            table: RwLock::new(InodeTable::new()),
            files: RwLock::new(HashMap::new()),
            next_fh: RwLock::new(1),
            pending_writes: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[allow(dead_code)]
    pub fn pending_writes_handle(&self) -> Arc<AtomicUsize> {
        self.pending_writes.clone()
    }

    fn alloc_fh(&self) -> u64 {
        let mut fh = self.next_fh.write();
        let val = *fh;
        *fh += 1;
        val
    }

    /// 拼接子路径
    fn child_path(parent: &str, name: &str) -> String {
        if parent == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent, name)
        }
    }

    /// 解析 mtime 字符串为 SystemTime
    fn parse_mtime(mtime: &str) -> SystemTime {
        mtime
            .parse::<u64>()
            .ok()
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap_or(UNIX_EPOCH)
    }

    /// 从 stat 信息构建 FileAttr
    fn make_attr(&self, ino: u64, is_dir: bool, size: u64, mtime: &str) -> FileAttr {
        let time = Self::parse_mtime(mtime);
        let (kind, perm, nlink) = if is_dir {
            (FileType::Directory, 0o755, 2u32)
        } else {
            (FileType::RegularFile, 0o644, 1u32)
        };
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind,
            perm,
            nlink,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// 写回上传（在 flush/release 时调用）
    fn writeback(&self, fh: u64) -> Result<(), i32> {
        let (path, data) = {
            let mut files = self.files.write();
            let Some(f) = files.get_mut(&fh) else {
                return Ok(());
            };
            if !f.dirty {
                return Ok(());
            }
            let Some(buf) = f.write_buf.as_ref() else {
                return Ok(());
            };
            f.dirty = false;
            (f.path.clone(), buf.clone())
        };

        self.pending_writes.fetch_add(1, Ordering::SeqCst);
        let result = self.client.upload_data(&path, &data);
        self.pending_writes.fetch_sub(1, Ordering::SeqCst);

        match result {
            Ok(_) => {
                log(&format!("写回完成: {}", path));
                Ok(())
            }
            Err(e) => {
                log(&format!("写回失败: {} - {}", path, e));
                Err(libc::EIO)
            }
        }
    }
}

impl Filesystem for LanShareFuse {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy();
        let parent_path = {
            let table = self.table.read();
            match table.path_of(parent) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            }
        };

        let path = Self::child_path(&parent_path, &name);
        match self.client.stat(&path) {
            Ok(stat) if stat.exists => {
                let ino = self.table.write().get_or_alloc(&path);
                let attr = self.make_attr(ino, stat.is_dir, stat.size, &stat.mtime);
                reply.entry(&ATTR_TTL, &attr, 0);
            }
            Ok(_) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let path = {
            let table = self.table.read();
            match table.path_of(ino) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            }
        };

        if path == "/" {
            // 根目录：不依赖远端 stat（根必然存在）
            match self.client.stat("/") {
                Ok(stat) => {
                    let attr = self.make_attr(ino, true, stat.size, &stat.mtime);
                    reply.attr(&ATTR_TTL, &attr);
                }
                Err(_) => {
                    // 离线时仍返回根目录基本属性
                    let attr = self.make_attr(ino, true, 0, "0");
                    reply.attr(&ATTR_TTL, &attr);
                }
            }
        } else {
            match self.client.stat(&path) {
                Ok(stat) if stat.exists => {
                    let attr = self.make_attr(ino, stat.is_dir, stat.size, &stat.mtime);
                    reply.attr(&ATTR_TTL, &attr);
                }
                Ok(_) => reply.error(libc::ENOENT),
                Err(_) => reply.error(libc::EIO),
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = {
            let table = self.table.read();
            match table.path_of(ino) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            }
        };

        let entries = match self.client.list_dir(&path) {
            Ok(e) => e,
            Err(_) => return reply.error(libc::EIO),
        };

        let mut table = self.table.write();

        // . 和 ..
        let parent_ino = if path == "/" {
            FUSE_ROOT_ID
        } else {
            let parent_path = match path.rfind('/') {
                Some(0) => "/".to_string(),       // "/foo" → 父为 "/"
                Some(i) => path[..i].to_string(), // "/foo/bar" → "/foo"
                None => "/".to_string(),
            };
            table.get_or_alloc(&parent_path)
        };

        let mut all: Vec<(u64, FileType, String)> = Vec::with_capacity(entries.len() + 2);
        all.push((ino, FileType::Directory, ".".to_string()));
        all.push((parent_ino, FileType::Directory, "..".to_string()));

        for e in &entries {
            let child = Self::child_path(&path, &e.name);
            let child_ino = table.get_or_alloc(&child);
            let kind = if e.is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            all.push((child_ino, kind, e.name.clone()));
        }
        drop(table);

        for (i, (ino, kind, name)) in all.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name) {
                break; // 缓冲区满
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let path = {
            let table = self.table.read();
            match table.path_of(ino) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            }
        };

        let accmode = flags & libc::O_ACCMODE;
        let want_write = accmode == libc::O_WRONLY || accmode == libc::O_RDWR;

        if want_write {
            if !self.client.can("write") {
                return reply.error(libc::EACCES);
            }
            // 检查文件大小（大文件保护）
            match self.client.stat(&path) {
                Ok(stat) if stat.exists && stat.size > MAX_WRITE_BUF_SIZE => {
                    log(&format!(
                        "文件过大({} bytes)，以只读打开: {}",
                        stat.size, path
                    ));
                    // 降级为只读
                    let data = match self.client.download(&path, 0) {
                        Ok(d) => d,
                        Err(_) => return reply.error(libc::EIO),
                    };
                    let fh = self.alloc_fh();
                    self.files.write().insert(
                        fh,
                        OpenFile {
                            path,
                            write_buf: None,
                            read_cache: Some(data),
                            dirty: false,
                            holds_lock: false,
                        },
                    );
                    return reply.opened(fh, 0);
                }
                Ok(stat) if stat.exists => {
                    // 下载现有内容到写缓冲
                    let data = match self.client.download(&path, 0) {
                        Ok(d) => d,
                        Err(_) => return reply.error(libc::EIO),
                    };
                    // 尝试文件锁
                    let holds_lock = match self.client.lock_file(&path, "exclusive", 60) {
                        Ok(_) => true,
                        Err(e) => {
                            log(&format!("文件锁获取失败({}): {}", path, e));
                            false
                        }
                    };
                    let fh = self.alloc_fh();
                    self.files.write().insert(
                        fh,
                        OpenFile {
                            path,
                            write_buf: Some(data),
                            read_cache: None,
                            dirty: false,
                            holds_lock,
                        },
                    );
                    reply.opened(fh, 0);
                }
                _ => reply.error(libc::ENOENT),
            }
        } else {
            // 只读打开：预读全部内容（LSP3 不支持随机读游标，整文件缓存最简单）
            let data = match self.client.download(&path, 0) {
                Ok(d) => d,
                Err(_) => return reply.error(libc::EIO),
            };
            let fh = self.alloc_fh();
            self.files.write().insert(
                fh,
                OpenFile {
                    path,
                    write_buf: None,
                    read_cache: Some(data),
                    dirty: false,
                    holds_lock: false,
                },
            );
            reply.opened(fh, 0);
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let files = self.files.read();
        let Some(f) = files.get(&fh) else {
            return reply.error(libc::EBADF);
        };
        let buf = f.write_buf.as_ref().or(f.read_cache.as_ref());
        match buf {
            Some(data) => {
                let off = offset as usize;
                if off >= data.len() {
                    reply.data(&[]);
                } else {
                    let end = (off + size as usize).min(data.len());
                    reply.data(&data[off..end]);
                }
            }
            None => reply.error(libc::EBADF),
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let mut files = self.files.write();
        let Some(f) = files.get_mut(&fh) else {
            return reply.error(libc::EBADF);
        };
        let Some(buf) = f.write_buf.as_mut() else {
            return reply.error(libc::EACCES);
        };

        let off = offset as usize;
        let end = off + data.len();

        // 大文件保护
        if end as u64 > MAX_WRITE_BUF_SIZE {
            return reply.error(libc::ENOSPC);
        }

        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[off..end].copy_from_slice(data);
        f.dirty = true;
        reply.written(data.len() as u32);
    }

    fn flush(&mut self, _req: &Request, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        match self.writeback(fh) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // 最终写回
        let _ = self.writeback(fh);

        // 释放文件锁 + 移除句柄
        let f = self.files.write().remove(&fh);
        if let Some(f) = f {
            if f.holds_lock {
                let _ = self.client.unlock_file(&f.path);
            }
        }
        reply.ok();
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let _ = (mode, flags);
        if !self.client.can("write") {
            return reply.error(libc::EACCES);
        }

        let name = name.to_string_lossy();
        let parent_path = {
            let table = self.table.read();
            match table.path_of(parent) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            }
        };
        let path = Self::child_path(&parent_path, &name);

        // 尝试文件锁
        let holds_lock = match self.client.lock_file(&path, "exclusive", 60) {
            Ok(_) => true,
            Err(e) => {
                log(&format!("文件锁获取失败({}): {}", path, e));
                false
            }
        };

        let ino = self.table.write().get_or_alloc(&path);
        let fh = self.alloc_fh();
        self.files.write().insert(
            fh,
            OpenFile {
                path: path.clone(),
                write_buf: Some(Vec::new()),
                read_cache: None,
                dirty: true, // 空文件也需要创建（flush 时上传）
                holds_lock,
            },
        );

        let attr = self.make_attr(ino, false, 0, "0");
        reply.created(&ATTR_TTL, &attr, 0, fh, 0);
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let _ = mode;
        if !self.client.can("mkdir") {
            return reply.error(libc::EACCES);
        }

        let name = name.to_string_lossy();
        let parent_path = {
            let table = self.table.read();
            match table.path_of(parent) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            }
        };
        let path = Self::child_path(&parent_path, &name);

        match self.client.mkdir(&path) {
            Ok(()) => {
                let ino = self.table.write().get_or_alloc(&path);
                let attr = self.make_attr(ino, true, 0, "0");
                reply.entry(&ATTR_TTL, &attr, 0);
            }
            Err(e) => {
                log(&format!("mkdir 失败({}): {}", path, e));
                reply.error(libc::EIO)
            }
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        if !self.client.can("delete") {
            return reply.error(libc::EACCES);
        }

        let name = name.to_string_lossy();
        let parent_path = {
            let table = self.table.read();
            match table.path_of(parent) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            }
        };
        let path = Self::child_path(&parent_path, &name);

        match self.client.delete(&path, false) {
            Ok(()) => {
                self.table.write().remove_path(&path);
                reply.ok();
            }
            Err(e) => {
                log(&format!("删除失败({}): {}", path, e));
                reply.error(libc::EIO)
            }
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        if !self.client.can("delete") {
            return reply.error(libc::EACCES);
        }

        let name = name.to_string_lossy();
        let parent_path = {
            let table = self.table.read();
            match table.path_of(parent) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            }
        };
        let path = Self::child_path(&parent_path, &name);

        match self.client.delete(&path, true) {
            Ok(()) => {
                self.table.write().remove_path(&path);
                reply.ok();
            }
            Err(e) => {
                log(&format!("rmdir 失败({}): {}", path, e));
                reply.error(libc::EIO)
            }
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &std::ffi::OsStr,
        newparent: u64,
        newname: &std::ffi::OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        if !self.client.can("rename") {
            return reply.error(libc::EACCES);
        }

        let name = name.to_string_lossy();
        let newname = newname.to_string_lossy();
        let (old_path, new_path) = {
            let table = self.table.read();
            let pp = match table.path_of(parent) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            };
            let np = match table.path_of(newparent) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            };
            (
                Self::child_path(&pp, &name),
                Self::child_path(&np, &newname),
            )
        };

        match self.client.rename(&old_path, &new_path) {
            Ok(()) => {
                self.table.write().rename_path(&old_path, &new_path);
                reply.ok();
            }
            Err(e) => {
                log(&format!("重命名失败({} -> {}): {}", old_path, new_path, e));
                reply.error(libc::EIO)
            }
        }
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: fuser::ReplyStatfs) {
        // 报告一个合理的虚拟容量
        reply.statfs(
            1024 * 1024, // blocks（512B 单位 → 512MB 虚拟）
            512 * 1024,  // bfree
            512 * 1024,  // bavail
            1_000_000,   // files
            900_000,     // ffree
            512,         // bsize
            255,         // namelen
            512,         // frsize
        );
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // 只处理 truncate（size 变更）
        let Some(new_size) = size else {
            // 无 size 变更，返回当前属性
            let path = {
                let table = self.table.read();
                match table.path_of(ino) {
                    Some(p) => p.to_string(),
                    None => return reply.error(libc::ENOENT),
                }
            };
            let (is_dir, file_size) = match self.client.stat(&path) {
                Ok(e) => (e.is_dir, e.size),
                Err(_) => return reply.error(libc::EIO),
            };
            let attr = self.make_attr(ino, is_dir, file_size, "0");
            return reply.attr(&ATTR_TTL, &attr);
        };

        if !self.client.can("write") {
            return reply.error(libc::EACCES);
        }
        if new_size > MAX_WRITE_BUF_SIZE {
            return reply.error(libc::ENOSPC);
        }

        let path = {
            let table = self.table.read();
            match table.path_of(ino) {
                Some(p) => p.to_string(),
                None => return reply.error(libc::ENOENT),
            }
        };

        // 下载 → 截断 → 上传
        let mut data = match self.client.download(&path, 0) {
            Ok(d) => d,
            Err(_) => return reply.error(libc::EIO),
        };
        data.resize(new_size as usize, 0);
        match self.client.upload_data(&path, &data) {
            Ok(_) => {
                let attr = self.make_attr(ino, false, new_size, "0");
                reply.attr(&ATTR_TTL, &attr);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }
}

/// 挂载 FUSE 文件系统（阻塞直到卸载）
pub fn mount_fuse(
    client: Arc<LspShareClient>,
    mountpoint: &std::path::Path,
    options: Vec<MountOption>,
) -> Result<fuser::BackgroundSession, std::io::Error> {
    let fs = LanShareFuse::new(client);
    fuser::spawn_mount2(fs, mountpoint, &options)
}
