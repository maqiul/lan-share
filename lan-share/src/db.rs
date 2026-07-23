//! SQLite 数据库模块
//! 用户管理 / 全局设置 / 用户设置 / 会话管理

use bcrypt::{hash, verify, DEFAULT_COST};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

/// 用户记录
#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: String, // 'admin' | 'user'
    pub shared_dir: Option<String>,
    pub must_change_password: bool,
    /// 权限列表（逗号分隔）：read,write,delete,rename,share,mkdir
    pub permissions: String,
    /// 配额（MB），0 表示不限
    pub quota_mb: i64,
}

impl User {
    /// 检查是否有某项权限（admin 拥有全部权限）
    pub fn can(&self, perm: &str) -> bool {
        if self.role == "admin" {
            return true;
        }
        self.permissions.split(',').any(|p| p.trim() == perm)
    }

    /// 是否可读（列目录/下载）
    pub fn can_read(&self) -> bool { self.can("read") }
    /// 是否可写（上传/创建文件）
    pub fn can_write(&self) -> bool { self.can("write") }
    /// 是否可删除
    pub fn can_delete(&self) -> bool { self.can("delete") }
    /// 是否可重命名
    pub fn can_rename(&self) -> bool { self.can("rename") }
    /// 是否可创建分享链接
    pub fn can_share(&self) -> bool { self.can("share") }
    /// 是否可创建目录
    pub fn can_mkdir(&self) -> bool { self.can("mkdir") }
}

/// 数据库包装（线程安全）
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// 打开或创建数据库，自动建表 + 确保 admin 账号存在
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self { conn: Mutex::new(conn) };
        db.init_schema()?;
        db.ensure_admin()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                shared_dir TEXT,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                permissions TEXT NOT NULL DEFAULT 'read,write,delete,rename,share,mkdir',
                quota_mb INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS admin_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_settings (
                user_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (user_id, key),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS shares (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT,
                download_count INTEGER NOT NULL DEFAULT 0,
                max_downloads INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                path TEXT,
                detail TEXT,
                ip TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            ",
        )?;

        // 迁移：为已有 users 表添加 permissions 列
        let has_permissions: bool = conn
            .prepare("PRAGMA table_info(users)")
            .and_then(|mut stmt| {
                let cols: Vec<String> = stmt
                    .query_map([], |row| row.get::<_, String>(1))?
                    .filter_map(|r| r.ok())
                    .collect();
                Ok(cols.iter().any(|c| c == "permissions"))
            })
            .unwrap_or(false);

        if !has_permissions {
            let _ = conn.execute(
                "ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL DEFAULT 'read,write,delete,rename,share,mkdir'",
                [],
            );
        }

        // 迁移：为已有 users 表添加 quota_mb 列
        let has_quota: bool = conn
            .prepare("PRAGMA table_info(users)")
            .and_then(|mut stmt| {
                let cols: Vec<String> = stmt
                    .query_map([], |row| row.get::<_, String>(1))?
                    .filter_map(|r| r.ok())
                    .collect();
                Ok(cols.iter().any(|c| c == "quota_mb"))
            })
            .unwrap_or(false);

        if !has_quota {
            let _ = conn.execute(
                "ALTER TABLE users ADD COLUMN quota_mb INTEGER NOT NULL DEFAULT 0",
                [],
            );
        }

        Ok(())
    }

    /// 确保 admin 账号存在（admin/admin123，首次登录强制改密）
    fn ensure_admin(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM users WHERE username = 'admin'", [], |r| {
                r.get(0)
            })?;
        if count == 0 {
            let pw_hash = hash("admin123", DEFAULT_COST).unwrap_or_default();
            conn.execute(
                "INSERT INTO users (username, password_hash, role, shared_dir, must_change_password)
                 VALUES ('admin', ?1, 'admin', NULL, 1)",
                params![pw_hash],
            )?;
            tracing::info!("Created default admin account (admin/admin123)");
        }
        Ok(())
    }

    // 认证

    /// 验证用户名密码，成功返回 User
    pub fn verify_login(&self, username: &str, password: &str) -> Option<User> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare(
                "SELECT id, username, password_hash, role, shared_dir, must_change_password, permissions, quota_mb
                 FROM users WHERE username = ?1",
            )
            .ok()?;
        let (pw_hash, user) = stmt
            .query_row(params![username], |row| {
                Ok((
                    row.get::<_, String>(2)?,
                    User {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        role: row.get(3)?,
                        shared_dir: row.get(4)?,
                        must_change_password: row.get::<_, i64>(5)? != 0,
                        permissions: row.get(6)?,
                        quota_mb: row.get(7)?,
                    },
                ))
            })
            .ok()?;
        if verify(password, &pw_hash).unwrap_or(false) {
            Some(user)
        } else {
            None
        }
    }

    // 会话管理

    /// 创建会话，返回 token（24h 有效）
    pub fn create_session(&self, user_id: i64) -> Result<String, rusqlite::Error> {
        let token = uuid::Uuid::new_v4().to_string();
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // 登录时顺便清理过期会话（低频操作，不影响 verify 性能）
        let _ = conn.execute("DELETE FROM sessions WHERE expires_at < datetime('now')", []);
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at)
             VALUES (?1, ?2, datetime('now', '+24 hours'))",
            params![token, user_id],
        )?;
        Ok(token)
    }

    /// 验证 token，返回对应 User（过期自动清理）
    pub fn verify_session(&self, token: &str) -> Option<User> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // 不再每次清理过期会话（查询已过滤 expires_at），清理移至 create_session
        let user_id: i64 = conn
            .query_row(
                "SELECT user_id FROM sessions WHERE token = ?1 AND expires_at > datetime('now')",
                params![token],
                |r| r.get(0),
            )
            .ok()?;
        self.get_user_by_id_inner(&conn, user_id)
    }

    /// 登出（删除会话）
    pub fn logout(&self, token: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute("DELETE FROM sessions WHERE token = ?1", params![token]);
    }

    // 用户管理（admin）

    fn get_user_by_id_inner(&self, conn: &Connection, user_id: i64) -> Option<User> {
        conn.query_row(
            "SELECT id, username, role, shared_dir, must_change_password, permissions, quota_mb FROM users WHERE id = ?1",
            params![user_id],
            |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    role: row.get(2)?,
                    shared_dir: row.get(3)?,
                    must_change_password: row.get::<_, i64>(4)? != 0,
                    permissions: row.get(5)?,
                    quota_mb: row.get(6)?,
                })
            },
        )
        .ok()
    }

    #[allow(dead_code)]
    pub fn get_user_by_id(&self, user_id: i64) -> Option<User> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        self.get_user_by_id_inner(&conn, user_id)
    }

    /// 列出所有用户
    pub fn list_users(&self) -> Vec<User> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare("SELECT id, username, role, shared_dir, must_change_password, permissions, quota_mb FROM users ORDER BY id")
            .unwrap();
        stmt.query_map([], |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                role: row.get(2)?,
                shared_dir: row.get(3)?,
                must_change_password: row.get::<_, i64>(4)? != 0,
                permissions: row.get(5)?,
                quota_mb: row.get(6)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    /// 创建用户（密码明文传入，内部 hash）
    pub fn create_user(
        &self,
        username: &str,
        password: &str,
        role: &str,
        shared_dir: Option<&str>,
        permissions: &str,
        quota_mb: i64,
    ) -> Result<i64, String> {
        let pw_hash = hash(password, DEFAULT_COST).map_err(|e| e.to_string())?;
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO users (username, password_hash, role, shared_dir, must_change_password, permissions, quota_mb)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)",
            params![username, pw_hash, role, shared_dir, permissions, quota_mb],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                "用户名已存在".to_string()
            }
            _ => e.to_string(),
        })?;
        Ok(conn.last_insert_rowid())
    }

    /// 删除用户（及其会话、设置）
    pub fn delete_user(&self, user_id: i64) -> Result<(), String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // 禁止删除最后一个 admin
        let admin_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users WHERE role = 'admin'", [], |r| r.get(0))
            .unwrap_or(0);
        let is_admin: bool = conn
            .query_row(
                "SELECT role = 'admin' FROM users WHERE id = ?1",
                params![user_id],
                |r| r.get(0),
            )
            .unwrap_or(false);
        if is_admin && admin_count <= 1 {
            return Err("不能删除最后一个管理员".to_string());
        }
        conn.execute("DELETE FROM users WHERE id = ?1", params![user_id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// 修改用户（shared_dir / role）
    pub fn update_user(
        &self,
        user_id: i64,
        role: Option<&str>,
        shared_dir: Option<Option<&str>>,
        permissions: Option<&str>,
        quota_mb: Option<i64>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = role {
            conn.execute("UPDATE users SET role = ?1 WHERE id = ?2", params![r, user_id])
                .map_err(|e| e.to_string())?;
        }
        if let Some(dir_opt) = shared_dir {
            conn.execute(
                "UPDATE users SET shared_dir = ?1 WHERE id = ?2",
                params![dir_opt, user_id],
            )
            .map_err(|e| e.to_string())?;
        }
        if let Some(p) = permissions {
            conn.execute(
                "UPDATE users SET permissions = ?1 WHERE id = ?2",
                params![p, user_id],
            )
            .map_err(|e| e.to_string())?;
        }
        if let Some(q) = quota_mb {
            conn.execute(
                "UPDATE users SET quota_mb = ?1 WHERE id = ?2",
                params![q, user_id],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// 修改密码（同时清除 must_change_password 标记）
    pub fn change_password(&self, user_id: i64, new_password: &str) -> Result<(), String> {
        let pw_hash = hash(new_password, DEFAULT_COST).map_err(|e| e.to_string())?;
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE users SET password_hash = ?1, must_change_password = 0 WHERE id = ?2",
            params![pw_hash, user_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    // 全局设置（admin_settings）

    pub fn get_admin_setting(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT value FROM admin_settings WHERE key = ?1",
            params![key],
            |r| r.get(0),
        )
        .ok()
    }

    pub fn set_admin_setting(&self, key: &str, value: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO admin_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        );
    }

    /// 读取全部全局设置
    pub fn get_all_admin_settings(&self) -> std::collections::HashMap<String, String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT key, value FROM admin_settings").unwrap();
        stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    // 用户设置（user_settings）

    #[allow(dead_code)]
    pub fn get_user_setting(&self, user_id: i64, key: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT value FROM user_settings WHERE user_id = ?1 AND key = ?2",
            params![user_id, key],
            |r| r.get(0),
        )
        .ok()
    }

    pub fn set_user_setting(&self, user_id: i64, key: &str, value: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO user_settings (user_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(user_id, key) DO UPDATE SET value = ?3",
            params![user_id, key, value],
        );
    }

    /// 读取某用户全部设置
    pub fn get_all_user_settings(&self, user_id: i64) -> std::collections::HashMap<String, String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare("SELECT key, value FROM user_settings WHERE user_id = ?1")
            .unwrap();
        stmt.query_map(params![user_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    // 分享链接

    /// 创建分享链接，返回 token
    pub fn create_share(&self, user_id: i64, path: &str, expires_hours: Option<i64>, max_downloads: Option<i64>) -> String {
        let token = uuid::Uuid::new_v4().simple().to_string();
        let expires_at = expires_hours.map(|h| {
            chrono::Utc::now() + chrono::Duration::hours(h)
        });
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO shares (token, user_id, path, expires_at, max_downloads) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                token,
                user_id,
                path,
                expires_at.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()),
                max_downloads,
            ],
        );
        token
    }

    /// 验证分享链接，返回 (user_id, path)，过期或不存在返回 None
    pub fn verify_share(&self, token: &str) -> Option<(i64, String)> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let result: Result<(i64, String, Option<String>, Option<i64>, i64), _> = conn.query_row(
            "SELECT user_id, path, expires_at, max_downloads, download_count FROM shares WHERE token = ?1",
            params![token],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        );
        let (user_id, path, expires_at, max_downloads, download_count) = result.ok()?;

        // 检查过期
        if let Some(exp) = expires_at {
            if let Ok(exp_time) = chrono::NaiveDateTime::parse_from_str(&exp, "%Y-%m-%d %H:%M:%S") {
                if chrono::Utc::now().naive_utc() > exp_time {
                    return None;
                }
            }
        }

        // 检查下载次数限制
        if let Some(max) = max_downloads {
            if download_count >= max {
                return None;
            }
        }

        Some((user_id, path))
    }

    /// 增加分享链接下载次数
    pub fn increment_share_download(&self, token: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "UPDATE shares SET download_count = download_count + 1 WHERE token = ?1",
            params![token],
        );
    }

    /// 删除分享链接
    pub fn delete_share(&self, token: &str) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute("DELETE FROM shares WHERE token = ?1", params![token]);
    }

    /// 列出某用户的全部分享链接
    pub fn list_shares(&self, user_id: i64) -> Vec<(String, String, Option<String>, i64)> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare("SELECT token, path, expires_at, download_count FROM shares WHERE user_id = ?1 ORDER BY created_at DESC")
            .unwrap();
        stmt.query_map(params![user_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, i64>(3)?))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    // 审计日志

    /// 记录审计日志
    pub fn audit_log(&self, user_id: Option<i64>, username: &str, action: &str, path: Option<&str>, detail: Option<&str>, ip: Option<&str>) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let _ = conn.execute(
            "INSERT INTO audit_log (user_id, username, action, path, detail, ip) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![user_id, username, action, path, detail, ip],
        );
    }

    /// 查询审计日志（最新 limit 条）
    pub fn get_audit_logs(&self, limit: i64) -> Vec<AuditLogEntry> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare("SELECT id, user_id, username, action, path, detail, ip, created_at FROM audit_log ORDER BY id DESC LIMIT ?1")
            .unwrap();
        stmt.query_map(params![limit], |row| {
            Ok(AuditLogEntry {
                id: row.get(0)?,
                user_id: row.get(1)?,
                username: row.get(2)?,
                action: row.get(3)?,
                path: row.get(4)?,
                detail: row.get(5)?,
                ip: row.get(6)?,
                created_at: row.get(7)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }
}

/// 审计日志条目
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditLogEntry {
    pub id: i64,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub action: String,
    pub path: Option<String>,
    pub detail: Option<String>,
    pub ip: Option<String>,
    pub created_at: String,
}
