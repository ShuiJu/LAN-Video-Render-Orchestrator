#Requires -Version 5.1
<#
.SYNOPSIS
    渲染机一键安装脚本
    - 检查并下载 ffmpeg / NVEncC64（安装到 tools\ 子目录）
    - 在桌面创建「视频渲染机」快捷方式（同时启动服务器 + 打开控制页面）
#>

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolsDir  = Join-Path $scriptDir "tools"

function Write-Step($msg) { Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "    [X] $msg" -ForegroundColor Red }

# ────────────────────────────────────────────
# 在 scriptDir、tools\ 以及系统 PATH 中查找可执行文件
# ────────────────────────────────────────────
function Find-Exe($name) {
    foreach ($dir in @($scriptDir, $toolsDir)) {
        $p = Join-Path $dir $name
        if (Test-Path $p) { return $p }
    }
    $inPath = (Get-Command $name -ErrorAction SilentlyContinue)
    if ($inPath) { return $inPath.Source }
    return $null
}

# ────────────────────────────────────────────
# 通用下载（带进度）
# ────────────────────────────────────────────
function Download-File($url, $dest) {
    Write-Host "      下载: $url" -ForegroundColor DarkGray
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "render-server-setup/1.0")
    $wc.DownloadFile($url, $dest)
}

# ────────────────────────────────────────────
# 查询 GitHub 最新 release
# ────────────────────────────────────────────
function Get-LatestRelease($repo) {
    $url = "https://api.github.com/repos/$repo/releases/latest"
    $headers = @{ "User-Agent" = "render-server-setup/1.0"; "Accept" = "application/vnd.github+json" }
    return Invoke-RestMethod -Uri $url -Headers $headers
}

# ════════════════════════════════════════════
# FFmpeg
# ════════════════════════════════════════════
function Ensure-FFmpeg {
    Write-Step "检查 ffmpeg.exe ..."
    $found = Find-Exe "ffmpeg.exe"
    if ($found) {
        Write-OK "已存在: $found"
        return
    }

    Write-Warn "未找到，从 BtbN/FFmpeg-Builds 下载 ..."
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

    try {
        $release = Get-LatestRelease "BtbN/FFmpeg-Builds"
        # 优先下载 essentials（体积小，只含可执行文件）
        $asset = $release.assets |
            Where-Object { $_.name -match "ffmpeg-master-latest-win64-gpl-essentials\.zip" } |
            Select-Object -First 1
        if (-not $asset) {
            $asset = $release.assets |
                Where-Object { $_.name -match "win64-gpl\.zip$" } |
                Select-Object -First 1
        }
        if (-not $asset) { throw "在 Release 中未找到适合 Windows x64 的 zip 资源" }

        $zipPath    = Join-Path $env:TEMP "ffmpeg_setup.zip"
        $extractDir = Join-Path $env:TEMP "ffmpeg_setup_extract"

        Download-File $asset.browser_download_url $zipPath

        Write-Host "      解压中..." -ForegroundColor DarkGray
        if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
        Expand-Archive -Path $zipPath -DestinationPath $extractDir

        # 找到 bin\ffmpeg.exe 或根目录 ffmpeg.exe
        $ffmpegExe = Get-ChildItem -Path $extractDir -Filter "ffmpeg.exe" -Recurse |
            Select-Object -First 1
        if (-not $ffmpegExe) { throw "解压后未找到 ffmpeg.exe" }

        Copy-Item $ffmpegExe.FullName (Join-Path $toolsDir "ffmpeg.exe") -Force

        # 同时复制 ffprobe（可选，但有用）
        $ffprobeExe = Get-ChildItem -Path $extractDir -Filter "ffprobe.exe" -Recurse |
            Select-Object -First 1
        if ($ffprobeExe) {
            Copy-Item $ffprobeExe.FullName (Join-Path $toolsDir "ffprobe.exe") -Force
        }

        Remove-Item $zipPath    -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

        Write-OK "ffmpeg 已安装到 tools\"
    } catch {
        Write-Err "下载 ffmpeg 失败: $_"
        Write-Host @"

  请手动下载 ffmpeg Windows 版本并将 ffmpeg.exe 放到以下任一位置：
    · $scriptDir\ffmpeg.exe
    · $toolsDir\ffmpeg.exe
  下载地址: https://github.com/BtbN/FFmpeg-Builds/releases

"@ -ForegroundColor Yellow
        throw "ffmpeg 安装失败，请手动安装后重新运行 setup.bat"
    }
}

# ════════════════════════════════════════════
# NVEncC64
# ════════════════════════════════════════════
function Ensure-NVEncC {
    Write-Step "检查 NVEncC64.exe ..."
    $found = Find-Exe "NVEncC64.exe"
    if ($found) {
        Write-OK "已存在: $found"
        return
    }

    Write-Warn "未找到，从 rigaya/NVEnc 下载 ..."
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

    try {
        $release = Get-LatestRelease "rigaya/NVEnc"
        # 匹配 NVEncC_x.xx_x64.zip
        $asset = $release.assets |
            Where-Object { $_.name -match "NVEncC.*x64.*\.zip" } |
            Select-Object -First 1
        if (-not $asset) {
            $asset = $release.assets |
                Where-Object { $_.name -match "\.zip$" } |
                Select-Object -First 1
        }
        if (-not $asset) { throw "在 Release 中未找到 NVEncC64 zip 资源" }

        $zipPath    = Join-Path $env:TEMP "nvencc_setup.zip"
        $extractDir = Join-Path $env:TEMP "nvencc_setup_extract"

        Download-File $asset.browser_download_url $zipPath

        Write-Host "      解压中..." -ForegroundColor DarkGray
        if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
        Expand-Archive -Path $zipPath -DestinationPath $extractDir

        $nvencExe = Get-ChildItem -Path $extractDir -Filter "NVEncC64.exe" -Recurse |
            Select-Object -First 1
        if (-not $nvencExe) { throw "解压后未找到 NVEncC64.exe" }

        $nvencDir = $nvencExe.DirectoryName

        # 复制 exe 及同目录所有 DLL（NVEncC 依赖若干 DLL）
        Copy-Item "$nvencDir\*" $toolsDir -Force

        Remove-Item $zipPath    -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

        Write-OK "NVEncC64 已安装到 tools\"
    } catch {
        Write-Err "下载 NVEncC64 失败: $_"
        Write-Host @"

  请手动下载 NVEncC64 Windows 版本并将 NVEncC64.exe（及同目录 DLL）放到以下任一位置：
    · $scriptDir\NVEncC64.exe
    · $toolsDir\NVEncC64.exe
  下载地址: https://github.com/rigaya/NVEnc/releases

"@ -ForegroundColor Yellow
        throw "NVEncC64 安装失败，请手动安装后重新运行 setup.bat"
    }
}

# ════════════════════════════════════════════
# 桌面快捷方式
# ════════════════════════════════════════════
function Create-DesktopShortcut {
    Write-Step "创建桌面快捷方式 ..."

    $launchBat   = Join-Path $scriptDir "launch.bat"
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $lnkPath     = Join-Path $desktopPath "视频渲染机.lnk"

    if (-not (Test-Path $launchBat)) {
        throw "未找到 launch.bat，请确认该文件与 setup.ps1 在同一目录。"
    }

    $shell = New-Object -ComObject WScript.Shell
    $sc    = $shell.CreateShortcut($lnkPath)
    $sc.TargetPath       = $launchBat
    $sc.WorkingDirectory = $scriptDir
    $sc.WindowStyle      = 7   # 最小化启动（cmd 窗口不挡屏）
    $sc.Description      = "启动渲染服务器并打开控制界面"

    # 优先用 exe 图标，其次用 html 图标
    $serverExe = Get-ChildItem -Path $scriptDir -Filter "render_server*.exe" |
        Select-Object -First 1
    if ($serverExe) {
        $sc.IconLocation = "$($serverExe.FullName),0"
    }

    $sc.Save()
    Write-OK "快捷方式已创建: $lnkPath"
}

# ════════════════════════════════════════════
# 主流程
# ════════════════════════════════════════════
Write-Host ""
Write-Host "  ╔══════════════════════════════════╗" -ForegroundColor White
Write-Host "  ║     渲染机环境安装程序            ║" -ForegroundColor White
Write-Host "  ╚══════════════════════════════════╝" -ForegroundColor White
Write-Host "  安装目录: $scriptDir"
Write-Host "  工具目录: $toolsDir"

$failed = $false

try { Ensure-FFmpeg  } catch { Write-Err $_.Exception.Message; $failed = $true }
try { Ensure-NVEncC  } catch { Write-Err $_.Exception.Message; $failed = $true }

if (-not $failed) {
    try { Create-DesktopShortcut } catch { Write-Err $_.Exception.Message; $failed = $true }
}

Write-Host ""
if ($failed) {
    Write-Host "  ══ 部分步骤失败，请根据上方提示手动处理后重新运行 setup.bat ══" -ForegroundColor Red
} else {
    Write-Host "  ══ 安装完成！双击桌面上的「视频渲染机」快捷方式即可启动。══" -ForegroundColor Green
}
Write-Host ""
