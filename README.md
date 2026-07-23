# LanShare v3.0 操作手册

局域网文件共享工具，基于自研 LSP3 二进制协议 + WebDAV 双通道。

---

## 快速开始

### 1. 启动服务端

```powershell
lan-share serve -d D:\share -p 18080 --webdav-port 18081 --pin 123456
```

启动后输出：
```
=== LanShare LSP v3.0 Server ===
Device: MAQIUL'PC
Shared dir: D:\share
PIN: 123456
LSP protocol: 192.168.0.248:18080
WebDAV:      http://192.168.0.248:18081
映射驱动器:  net use Z: \\192.168.0.248@18081\DavWWWRoot /user:share 123456
```

### 2. 三种使用方式

| 方式 | 适合场景 | 性能 |
|------|---------|------|
| **映射驱动器（WebDAV）** | 日常浏览、拖拽复制 | ⭐⭐⭐ |
| **CLI 命令行** | 脚本自动化、大文件传输 | ⭐⭐⭐⭐⭐ |
| **浏览器访问** | 临时查看、快速下载 | ⭐⭐ |

---

## 方式一：映射为网络驱动器（推荐日常使用）

### Windows（需先改一次注册表）

**第一步：管理员 PowerShell 执行（只需一次）：**
```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters /v BasicAuthLevel /t REG_DWORD /d 2 /f
net stop WebClient; net start WebClient
```

**第二步：映射驱动器：**
```powershell
net use Z: \\192.168.0.248@18081\DavWWWRoot /user:share 123456
```

**断开：**
```powershell
net use Z: /delete
```

**开机自动映射：**
```powershell
net use Z: \\192.168.0.248@18081\DavWWWRoot /user:share 123456 /persistent:yes
```

### Windows（RaiDrive，免注册表）

1. 下载安装 [RaiDrive](https://www.raidrive.com/)（免费版）
2. 点击「添加」→ 选 **WebDAV**
3. 填写：
   - 地址：`192.168.0.248`
   - 端口：`18081`
   - 用户名：`share`
   - 密码：`123456`
   - **取消勾选** SSL/TLS
4. 点击「连接」→ 资源管理器出现新盘符

### macOS

Finder → 前往 → 连接服务器（⌘K）：
```
http://192.168.0.248:18081
```
用户名 `share`，密码 `123456`。

### Linux

```bash
# 安装 davfs2
sudo apt install davfs2

# 挂载
sudo mkdir -p /mnt/lanshare
sudo mount -t davfs http://192.168.0.248:18081 /mnt/lanshare
# 输入用户名 share，密码 123456

# 卸载
sudo umount /mnt/lanshare
```

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
lan-share download 192.168.0.248:18080 /docs/readme.md -o .\readme.md --pin 123456
```

### 上传文件

```powershell
lan-share upload 192.168.0.248:18080 .\myfile.zip --pin 123456
lan-share upload 192.168.0.248:18080 .\photo.jpg -r /photos/photo.jpg --pin 123456
```

### 差异同步上传（只传变化部分，大文件神器）

```powershell
lan-share delta-upload 192.168.0.248:18080 .\big.zip --pin 123456
lan-share delta-upload 192.168.0.248:18080 .\vm.vmdk -r /backups/vm.vmdk --pin 123456
```

> 原理：rsync 风格的滚动校验 + 块级差异，只传修改过的块。10GB 文件改了几 MB，就只传几 MB。

### 删除文件

```powershell
lan-share delete 192.168.0.248:18080 /test.txt --pin 123456
lan-share delete 192.168.0.248:18080 /old_folder -r --pin 123456   # 递归删除目录
```

### 创建目录

```powershell
lan-share mkdir 192.168.0.248:18080 /new_folder --pin 123456
```

### 重命名/移动

```powershell
lan-share rename 192.168.0.248:18080 /old.txt /new.txt --pin 123456
lan-share rename 192.168.0.248:18080 /file.txt /docs/file.txt --pin 123456
```

### 查看文件信息

```powershell
lan-share stat 192.168.0.248:18080 /test.txt --pin 123456
```

输出：
```
📄 File Info:
--------------------------------------------------
Name:     test.txt
Path:     /test.txt
Size:     18 B (18)
Type:     File
Readonly: false
Modified: 2026-07-22 16:52:58
SHA-256:  a1b2c3...
```

---

## 方式三：Web 图形界面（零安装，全设备通用）

任何设备（电脑 / 手机 / 平板）打开浏览器访问：

```
http://192.168.0.248:18081
```

输入 PIN 码（`123456`）即可进入图形化文件管理器。

**Web UI 功能：**
- 🔐 PIN 码登录（会话内记住，刷新免重输）
- 📁 网格 / 列表双视图切换
- 🧭 面包屑导航 + 实时文件筛选
- ⬆ 拖拽上传 / 点击上传，带进度条队列
- ⬇ 一键下载，✏️ 重命名，🗑 删除，＋ 新建文件夹
- 🖱 右键菜单 + 键盘快捷键（`Del` 删除 / `F5` 刷新 / `Backspace` 返回上级）
- 📊 右侧栏：服务器状态、连接命令一键复制、运行时间实时跳动
- 🎨 深色"网络控制台"质感界面，自适应移动端

> Web UI 内嵌在服务端二进制里（`include_str!`），不依赖任何外部文件，单 exe 即可运行。
> 大文件批量传输仍建议用 CLI 的 LSP 协议（加密 + 差异同步，更快更安全）。

---

## 服务端参数详解

```
lan-share serve [OPTIONS]

Options:
  -p, --port <PORT>              LSP 协议端口 [默认: 9820]
  -n, --name <NAME>              设备名称 [默认: 计算机名]
  -d, --dir <DIR>                共享目录 [默认: ./shared]
      --pin <PIN>                配对 PIN 码 [默认: 123456]
      --webdav-port <PORT>       WebDAV 端口，0=禁用 [默认: 8080]
  -h, --help                     帮助
```

### 示例

```powershell
# 最简启动（共享当前目录的 shared 文件夹）
lan-share serve

# 指定目录和端口
lan-share serve -d E:\movies -p 20000 --webdav-port 20001

# 自定义设备名和 PIN
lan-share serve -d D:\share -n "老马的文件服务器" --pin 999888

# 只开 LSP 协议，不开 WebDAV
lan-share serve -d D:\share --webdav-port 0

# 多实例（不同目录不同端口）
lan-share serve -d D:\work -p 18080 --webdav-port 18081
lan-share serve -d E:\media -p 18090 --webdav-port 18091
```

---

## 端口说明

| 端口 | 协议 | 用途 |
|------|------|------|
| LSP 端口（默认 9820） | UDP 自研二进制协议 | CLI 高性能传输、加密、差异同步 |
| WebDAV 端口（默认 8080） | HTTP/WebDAV | 映射驱动器、浏览器访问 |

> ⚠️ 避免使用 Windows 保留端口区间（Hyper-V/WSL 占用），如 12295-12394。
> 查看保留区间：`netsh interface ipv4 show excludedportrange protocol=tcp`

---

## 安全机制

- **PIN 配对**：所有操作都需要 PIN 码认证
- **LSP 协议**：ECDH 密钥交换 + ChaCha20-Poly1305 端到端加密
- **WebDAV**：HTTP Basic Auth（局域网内使用）
- **路径沙箱**：所有文件操作限制在共享目录内，无法逃逸

---

## 常见问题

### Q: `net use` 报错 "系统错误 67"
**A:** Windows 默认禁止 HTTP 上的 Basic Auth。执行：
```powershell
# 管理员 PowerShell
reg add HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters /v BasicAuthLevel /t REG_DWORD /d 2 /f
net stop WebClient; net start WebClient
```
或者用 RaiDrive 代替。

### Q: 端口绑定报错 10013 PermissionDenied
**A:** 端口被 Windows Hyper-V 保留了。换一个端口，或查看保留区间：
```powershell
netsh interface ipv4 show excludedportrange protocol=tcp
```

### Q: 大文件传输用哪个？
**A:** 用 CLI 的 `delta-upload`（差异同步）或 `upload`，走 LSP 二进制协议，比 WebDAV 快得多。WebDAV 适合日常浏览和小文件。

### Q: 怎么开机自启动？
**A:** 方法一：把命令加到 Windows 任务计划程序。方法二：放到启动文件夹的快捷方式里：
```powershell
# 创建启动快捷方式（放到 shell:startup）
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\LanShare.lnk")
$Shortcut.TargetPath = "D:\lan-share\target\release\lan-share.exe"
$Shortcut.Arguments = "serve -d D:\share -p 18080 --webdav-port 18081 --pin 123456"
$Shortcut.Save()
```

### Q: 多台电脑怎么互相传？
**A:** 每台电脑都启动 `lan-share serve`，然后用 CLI 连对方的 IP:端口。或者都映射 WebDAV 驱动器，直接在资源管理器里拖。

### Q: 怎么添加到 PATH？
**A:**
```powershell
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";D:\lan-share\target\release", "User")
```
重开终端生效。

---

## 技术架构

```
┌─────────────────────────────────────────────┐
│              lan-share serve                 │
│                                             │
│  ┌─────────────────┐  ┌──────────────────┐  │
│  │  LSP3 二进制协议  │  │  WebDAV (HTTP)   │  │
│  │  UDP 端口: 18080 │  │  端口: 18081     │  │
│  │                 │  │                  │  │
│  │ • ECDH+ChaCha加密│  │ • PROPFIND/GET   │  │
│  │ • 二进制分块+ACK │  │ • PUT/DELETE     │  │
│  │ • 滑动窗口流控  │  │ • MKCOL/MOVE     │  │
│  │ • 拥塞控制     │  │ • LOCK/UNLOCK    │  │
│  │ • 差异同步     │  │ • Basic Auth     │  │
│  │ • LZ4/Zstd压缩 │  │                  │  │
│  └────────┬────────┘  └────────┬─────────┘  │
│           │                    │            │
│           └────────┬───────────┘            │
│                    │                        │
│              D:\share (共享目录)              │
└─────────────────────────────────────────────┘
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
└── lan-share/              # CLI 应用
    ├── Cargo.toml
    ├── src/
    │   ├── main.rs         # CLI 入口
    │   └── webdav.rs       # WebDAV 服务器 + 内嵌 Web UI 路由
    └── assets/
        └── index.html      # Web 图形界面（编译时内嵌进二进制）
```