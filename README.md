# LanShare v3.0 操作手册

局域网文件共享工具，基于自研 LSP3 二进制协议 + WSP WebSocket 协议双通道。

---

## 快速开始

### 1. 启动服务端

```powershell
lan-share serve -d D:\share -p 18080 --web-port 18081 --pin 123456
```

启动后输出：
```
=== LanShare LSP v3.0 Server ===
Device: MAQIUL'PC
Shared dir: D:\share
PIN: 123456
LSP protocol: 192.168.0.248:18080
Web UI:      http://192.168.0.248:18081
```

### 2. 三种使用方式

| 方式 | 适合场景 | 性能 |
|------|---------|------|
| **WinFsp 挂载（客户端）** | 日常浏览、拖拽复制，像本地磁盘一样操作 | ⭐⭐⭐⭐ |
| **CLI 命令行** | 脚本自动化、大文件传输 | ⭐⭐⭐⭐⭐ |
| **浏览器访问** | 临时查看、快速下载、全设备通用 | ⭐⭐⭐ |

---

## 方式一：WinFsp 挂载为本地磁盘（推荐日常使用）

### 前提

安装 [WinFsp](https://winfsp.dev/rel/) 运行时（一次性，约 5MB）。

### 使用

```powershell
# 简易模式（PIN 认证）
lanshare-client.exe --server 192.168.0.248:18081 --pin 123456 --drive L

# 账号模式
lanshare-client.exe --server 192.168.0.248:18081 -u 用户名 -p 密码 --drive L
```

挂载后资源管理器出现 L 盘，像本地磁盘一样拖拽、复制、粘贴。

### 配置文件（双击自动挂载）

首次运行 `lanshare-client.exe` 会在同目录生成 `lanshare-client.toml`：

```toml
# 服务器地址（IP:端口）
server = "192.168.0.248:18081"

# 认证方式：pin 或 account
auth = "pin"
pin = "123456"
# username = "user"
# password = "pass"

# 挂载盘符
drive = "L"
```

配置好后双击 exe 即可自动挂载。

---

## 方式二：CLI 命令行（高性能传输）

### 列出文件

```powershell
lan-share list 192.168.0.248:18080 --pin 123456
lan-share list 192.168.0.248:18080 /docs --pin 123456        # 子目录
lan-share list 192.168.0.248:18080 -r --pin 123456           # 递归列出
```

### 下载文件

```powershell
lan-share download 192.168.0.248:18080 /test.txt -o .\test.txt --pin 123456
```

### 上传文件

```powershell
lan-share upload 192.168.0.248:18080 .\myfile.zip --pin 123456
lan-share upload 192.168.0.248:18080 .\photo.jpg -r /photos/photo.jpg --pin 123456
```

### 差异同步上传（只传变化部分，大文件神器）

```powershell
lan-share delta-upload 192.168.0.248:18080 .\big.zip --pin 123456
```

> 原理：rsync 风格的滚动校验 + 块级差异，只传修改过的块。10GB 文件改了几 MB，就只传几 MB。

### 删除 / 创建目录 / 重命名 / 查看信息

```powershell
lan-share delete 192.168.0.248:18080 /test.txt --pin 123456
lan-share delete 192.168.0.248:18080 /old_folder -r --pin 123456
lan-share mkdir 192.168.0.248:18080 /new_folder --pin 123456
lan-share rename 192.168.0.248:18080 /old.txt /new.txt --pin 123456
lan-share stat 192.168.0.248:18080 /test.txt --pin 123456
```

### 发现局域网服务器

```powershell
lan-share discover
```

---

## 方式三：Web 图形界面（零安装，全设备通用）

任何设备（电脑 / 手机 / 平板）打开浏览器访问：

```
http://192.168.0.248:18081
```

**Web UI 功能：**
- 🔐 PIN 码 / 账号密码登录
- 📁 网格 / 列表双视图切换
- 🧭 面包屑导航 + 实时文件筛选
- ⬆ 拖拽上传 / 点击上传，带进度条队列
- ⬇ 一键下载（WSP 协议），✏️ 重命名，🗑 删除，＋ 新建文件夹
- 📦 文件夹打包 zip 下载
- 🔗 文件分享链接（可设过期时间和下载次数）
- 👁 文件预览（图片/文本/视频/音频/PDF）
- 🖱 右键菜单 + 键盘快捷键
- 👥 多用户管理（admin 可创建用户、分配权限和配额）
- 📋 审计日志
- 🌐 中英文双语
- ⚙️ 设置面板（端口/PIN/共享目录/简易模式切换）

> Web UI 内嵌在服务端二进制里（`include_str!`），不依赖任何外部文件，单 exe 即可运行。
> 所有文件操作走 WSP（WebSocket 自研协议），不再依赖 WebDAV。

---

## 服务端参数详解

```
lan-share serve [OPTIONS]

Options:
  -p, --port <PORT>              LSP 协议端口 [默认: 9820]
  -n, --name <NAME>              设备名称 [默认: 计算机名]
  -d, --dir <DIR>                共享目录 [默认: ./shared]
      --pin <PIN>                配对 PIN 码 [默认: 123456]
      --web-port <PORT>          Web 界面端口，0=禁用 [默认: 8080]
      --no-browser               启动后不自动打开浏览器
  -h, --help                     帮助
```

### 示例

```powershell
# 最简启动（共享当前目录的 shared 文件夹）
lan-share serve

# 指定目录和端口
lan-share serve -d E:\movies -p 20000 --web-port 20001

# 自定义设备名和 PIN
lan-share serve -d D:\share -n "老马的文件服务器" --pin 999888

# 只开 LSP 协议，不开 Web 界面
lan-share serve -d D:\share --web-port 0

# 多实例（不同目录不同端口）
lan-share serve -d D:\work -p 18080 --web-port 18081
lan-share serve -d E:\media -p 18090 --web-port 18091
```

### GUI 模式（双击启动）

直接双击 `lan-share.exe`（不带参数），自动读取同目录 `lanshare.toml` 配置，启动后托盘常驻、自动打开浏览器。

---

## 端口说明

| 端口 | 协议 | 用途 |
|------|------|------|
| LSP 端口（默认 9820） | UDP 自研二进制协议 | CLI 高性能传输、加密、差异同步 |
| Web 端口（默认 8080） | HTTP + WebSocket | Web UI、REST API、WSP 文件操作 |
| 发现端口（固定 9999） | UDP 广播 | 局域网自动发现服务器 |

> ⚠️ 避免使用 Windows 保留端口区间（Hyper-V/WSL 占用），如 12295-12394。
> 查看保留区间：`netsh interface ipv4 show excludedportrange protocol=tcp`

---

## 安全机制

- **PIN / 账号密码**：简易模式用 PIN，账号模式用用户名+密码（bcrypt 哈希）
- **LSP 协议**：ECDH 密钥交换 + ChaCha20-Poly1305 端到端加密
- **WSP 协议**：WebSocket + session token 认证
- **路径沙箱**：所有文件操作限制在共享目录内，无法逃逸
- **暴力破解防护**：连续登录失败自动锁定 15 分钟
- **权限控制**：read / write / delete / rename / share / mkdir 六项独立权限
- **审计日志**：记录登录、文件操作、设置变更等关键事件

---

## 常见问题

### Q: 端口绑定报错 10013 PermissionDenied
**A:** 端口被 Windows Hyper-V 保留了。换一个端口，或查看保留区间：
```powershell
netsh interface ipv4 show excludedportrange protocol=tcp
```

### Q: 大文件传输用哪个？
**A:** 用 CLI 的 `delta-upload`（差异同步）或 `upload`，走 LSP 二进制协议，加密 + 压缩 + 差异同步，最快最安全。

### Q: 怎么开机自启动？
**A:** 方法一：把命令加到 Windows 任务计划程序。方法二：放到启动文件夹的快捷方式里：
```powershell
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\LanShare.lnk")
$Shortcut.TargetPath = "D:\lan-share\target\release\lan-share.exe"
$Shortcut.Arguments = "serve -d D:\share -p 18080 --web-port 18081 --pin 123456"
$Shortcut.Save()
```

### Q: 多台电脑怎么互相传？
**A:** 每台电脑都启动 `lan-share serve`，然后用 CLI 连对方的 IP:端口，或用客户端挂载对方的共享目录。

### Q: 怎么添加到 PATH？
**A:**
```powershell
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";D:\lan-share\target\release", "User")
```
重开终端生效。

---

## 技术架构

```
┌──────────────────────────────────────────────────┐
│                lan-share serve                    │
│                                                  │
│  ┌──────────────────┐  ┌───────────────────────┐ │
│  │  LSP3 二进制协议   │  │  Web 服务 (HTTP)      │ │
│  │  UDP 端口: 9820   │  │  端口: 8080           │ │
│  │                  │  │                       │ │
│  │ • ECDH+ChaCha加密 │  │ • Web UI (内嵌SPA)    │ │
│  │ • 二进制分块+ACK  │  │ • REST API            │ │
│  │ • 滑动窗口流控   │  │ • WSP WebSocket 协议   │ │
│  │ • 拥塞控制      │  │ • 局域网发现 (UDP)     │ │
│  │ • 差异同步      │  │                       │ │
│  │ • LZ4/Zstd压缩  │  │                       │ │
│  └────────┬─────────┘  └──────────┬────────────┘ │
│           │                       │              │
│           └───────────┬───────────┘              │
│                       │                          │
│                 D:\share (共享目录)                │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│              lanshare-client (WinFsp)             │
│                                                  │
│  • 局域网自动扫描发现服务器                         │
│  • PIN / 账号密码认证                             │
│  • 挂载为本地磁盘（L: 盘）                        │
│  • 通过 WSP WebSocket 协议读写文件                 │
└──────────────────────────────────────────────────┘
```

---

## 文件结构

```
D:\lan-share\
├── Cargo.toml              # Workspace 配置
├── README.md               # 本手册
├── lsp-protocol/           # LSP3 协议库（可独立复用）
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # 库入口
│       ├── protocol.rs     # 帧编解码、消息定义
│       ├── client.rs       # 客户端实现
│       ├── server.rs       # 服务端实现
│       ├── crypto.rs       # ECDH + ChaCha20-Poly1305
│       ├── transport.rs    # UDP 传输层（帧收发/加密/压缩）
│       ├── retransmission.rs  # 重传 + RTT 估算
│       ├── flow_control.rs    # 滑动窗口流控
│       ├── congestion.rs      # 拥塞控制（慢启动/快恢复）
│       ├── diff_transfer.rs   # 差异传输（rsync 风格）
│       ├── compression.rs     # LZ4/Zstd 压缩
│       └── error.rs           # 错误类型
├── lan-share/              # 服务端
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs         # CLI 入口 + GUI 模式
│   │   ├── server.rs       # HTTP 服务器（Web UI + API + WSP 路由）
│   │   ├── api.rs          # REST API（登录/用户/设置/分享/审计）
│   │   ├── wsp.rs          # WSP WebSocket 协议（文件操作）
│   │   ├── db.rs           # SQLite 数据库（用户/会话/设置/审计）
│   │   └── discovery.rs    # 局域网 UDP 广播发现
│   └── assets/
│       └── index.html      # Web 图形界面（编译时内嵌进二进制）
└── lanshare-client/        # WinFsp 客户端
    ├── Cargo.toml
    └── src/
        ├── main.rs         # 入口 + 自动发现 + 交互选择
        ├── fs.rs           # WinFsp 文件系统实现
        └── wsp_client.rs   # WSP 协议客户端
```
