@echo off
setlocal enabledelayedexpansion

REM LanShare Client 单独打包脚本
REM 输出：D:\lan-share\dist\lanshare-client-v0.1.0\
REM   ├── lanshare-client.exe
REM   └── README.txt
REM （WinFsp DLL 是 delayload，用户需要先装 WinFsp 2.x）

set ROOT=D:\lan-share
set OUT=%ROOT%\dist\lanshare-client-v0.1.0
set VER=0.1.0

echo === LanShare Client 构建 + 打包 ===

REM 1. 编译
echo [1/3] 编译 Rust WinFsp 客户端...
set PATH=C:\Users\maqiu\.cargo\bin;%PATH%
cd /d %ROOT%
cargo build --release -p lanshare-client
if errorlevel 1 (
    echo   X cargo 编译失败
    exit /b 1
)

REM 2. 准备分发目录
echo [2/3] 准备分发目录 %OUT% ...
if exist %OUT% rmdir /s /q %OUT%
mkdir %OUT%
copy /y %ROOT%\target\release\lanshare-client.exe %OUT%\lanshare-client.exe >nul

REM 3. 写 README
(
    echo LanShare Client v%VER%
    echo =====================================
    echo.
    echo LanShare 客户端：将远程 LanShare 共享挂载为本地盘符（只读）。
    echo.
    echo 【依赖】
    echo   - Windows 10 / 11
    echo   - WinFsp 2.x：https://winfsp.dev （首次运行前安装）
    echo   - 无需 .NET / VC++ 运行时：本程序为 Rust 原生
    echo.
    echo 【使用】
    echo   1. 安装 WinFsp（一次性）
    echo   2. 双击 lanshare-client.exe 启动：
    echo      - 第一次：自动扫描局域网，选择服务器，输入 PIN/账号密码
    echo      - 之后：自动读取同目录 lanshare-client.toml 配置直接挂载
    echo.
    echo   或命令行：
    echo     lanshare-client.exe --server 192.168.1.100:8080 --pin 123456 --mount L:
    echo     lanshare-client.exe --server 192.168.1.100:8080 -u alice -p secret --mount M:
    echo.
    echo 【盘符说明】
    echo   --mount L:    指定盘符
    echo   --mount *     自动分配空闲盘符
    echo.
    echo 【退出】
    echo   关闭控制台窗口即可卸载盘符。
) > %OUT%\README.txt

echo [3/3] 打包完成
echo.
echo 输出目录：%OUT%
dir %OUT%
endlocal