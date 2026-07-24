@echo off
setlocal enabledelayedexpansion

REM LanShare Server 单独打包脚本
REM 输出：D:\lan-share\dist\lanshare-server-v0.1.0\

set ROOT=D:\lan-share
set OUT=%ROOT%\dist\lanshare-server-v0.1.0
set VER=0.1.0

echo === LanShare Server 构建 + 打包 ===

echo [1/3] 编译 Rust 服务端...
set PATH=C:\Users\maqiu\.cargo\bin;%PATH%
cd /d %ROOT%
cargo build --release -p lan-share
if errorlevel 1 (
    echo   X cargo 编译失败
    exit /b 1
)

echo [2/3] 准备分发目录 %OUT% ...
if exist %OUT% rmdir /s /q %OUT%
mkdir %OUT%
copy /y %ROOT%\target\release\lan-share.exe %OUT%\lanshare-server.exe >nul

echo [3/3] 写 README...
(
    echo LanShare Server v%VER%
    echo =====================================
    echo.
    echo LanShare 服务端：局域网共享 + Web 管理界面 + WSP 自研协议。
    echo.
    echo 【依赖】
    echo   无外部依赖：单文件 exe，含 Rust runtime。
    echo.
    echo 【使用】
    echo   直接双击启动。默认监听 8080 端口。
    echo   Web UI：浏览器打开 http://本机IP:8080
    echo.
    echo 【命令行参数】
    echo   --port N       指定端口（默认 8080）
    echo   --host 0.0.0.0 监听所有网卡（默认）
    echo   --config FILE  指定配置文件路径
    echo.
    echo 【配置】
    echo   首次启动时在同目录生成 lanshare.toml，编辑后重启生效。
) > %OUT%\README.txt

echo 输出目录：%OUT%
dir %OUT%
endlocal