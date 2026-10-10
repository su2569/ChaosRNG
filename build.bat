@echo off
rem Chaos RNG (Go / Windows) build script
setlocal

rem --- 切到本脚本所在目录，避免双击时工作目录不对 ---
cd /d "%~dp0"

rem --- 检查是否在正确的工程目录 ---
if not exist "go.mod" (
    echo [build] FAILED: go.mod not found in "%CD%"
    echo [build] Put this build.bat in the chaos_rng_go folder ^(the one with go.mod^).
    exit /b 1
)

rem --- 检查 go 是否可用 ---
where go >nul 2>nul
if errorlevel 1 (
    echo [build] FAILED: "go" not found in PATH. Install Go or add it to PATH.
    exit /b 1
)

set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0

go build -trimpath -ldflags "-s -w" -o chaos_rng.exe .
if errorlevel 1 (
    echo [build] FAILED
    exit /b 1
)

echo [build] OK -^> %CD%\chaos_rng.exe
endlocal