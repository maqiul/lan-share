# LanShare XP Client

Windows XP 及以上可用的 LanShare 命令行客户端。纯 C 实现，零外部依赖（仅 Winsock2）。

## 编译

### 方法一：MinGW（推荐）

```bash
gcc -O2 -o lanshare-xp.exe lanshare_xp.c -lws2_32
```

### 方法二：MSVC（VS2005/2008/2010 均可）

```bat
cl /O2 /Fe:lanshare-xp.exe lanshare_xp.c ws2_32.lib
```

### 方法三：TCC（Tiny C Compiler，超小）

```bash
tcc -o lanshare-xp.exe lanshare_xp.c -lws2_32
```

## 使用

```
lanshare-xp <server:port> --pin <pin> <command> [args]
```

### 命令

| 命令 | 说明 | 示例 |
|------|------|------|
| `list [path]` | 列出目录 | `lanshare-xp 192.168.0.100:8080 --pin 123456 list /` |
| `get <remote> <local>` | 下载文件 | `lanshare-xp 192.168.0.100:8080 --pin 123456 get /test.txt test.txt` |
| `put <local> <remote>` | 上传文件 | `lanshare-xp 192.168.0.100:8080 --pin 123456 put photo.jpg /photos/photo.jpg` |
| `mkdir <path>` | 创建目录 | `lanshare-xp 192.168.0.100:8080 --pin 123456 mkdir /new_folder` |
| `del <path>` | 删除文件/目录 | `lanshare-xp 192.168.0.100:8080 --pin 123456 del /old.txt` |

### 完整示例

```bat
:: 列出根目录
lanshare-xp 192.168.0.100:8080 --pin 123456 list /

:: 下载文件到当前目录
lanshare-xp 192.168.0.100:8080 --pin 123456 get /docs/readme.md readme.md

:: 上传文件
lanshare-xp 192.168.0.100:8080 --pin 123456 put backup.zip /backups/backup.zip

:: 创建目录
lanshare-xp 192.168.0.100:8080 --pin 123456 mkdir /photos/2026

:: 删除文件
lanshare-xp 192.168.0.100:8080 --pin 123456 del /temp/old.log
```

## 系统要求

- Windows XP SP3 及以上（XP / Vista / 7 / 8 / 10 / 11）
- 无其他依赖，单 exe 即可运行
- 生成的 exe 约 30-50 KB

## 协议

通过 WSP（WebSocket Share Protocol）与服务端通信：
- WebSocket 连接 → `/wsp`
- 自定义 16 字节二进制帧头
- PIN 码认证
