@echo off
chcp 65001 >nul
title 渲染机安装程序

echo.
echo  正在以管理员身份检查...（如弹出 UAC 请允许）
echo.

:: 使用 PowerShell 运行安装脚本，绕过执行策略限制
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1"

echo.
pause
