@echo off
chcp 65001 >nul
cd /d "%~dp0"

:: ── 查找服务器可执行文件（兼容不同版本号命名） ──
set "SERVER_EXE="
for /f "delims=" %%f in ('dir /b "%~dp0render_server*.exe" 2^>nul') do (
    set "SERVER_EXE=%%f"
)

if "%SERVER_EXE%"=="" (
    echo [错误] 未在当前目录找到 render_server*.exe
    echo 请确认可执行文件与此脚本在同一目录。
    pause
    exit /b 1
)

:: ── 检查端口 8088 是否已被占用 ──
netstat -an 2>nul | findstr ":8088 " | findstr /i "LISTENING" >nul 2>&1
if %errorlevel% equ 0 (
    echo 渲染服务器已在运行 ^(端口 8088^)，跳过启动。
) else (
    echo 正在启动渲染服务器: %SERVER_EXE%
    start "渲染服务器" /min "%~dp0%SERVER_EXE%"
    :: 稍等片刻让服务器完成初始化
    timeout /t 1 /nobreak >nul
)

:: ── 在默认浏览器中打开控制页面 ──
start "" "%~dp0NvencC64.html"

exit /b 0
