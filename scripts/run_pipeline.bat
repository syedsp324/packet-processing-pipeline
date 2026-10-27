
@echo off
setlocal

cd /d "%~dp0.."

if "%~1"=="" (
    echo Usage: scripts\run_pipeline.bat ^<pcap_file^>
    echo Example: scripts\run_pipeline.bat data\traces\dns.cap
    exit /b 1
)

if not exist "%~1" (
    echo Error: PCAP file not found: %~1
    exit /b 1
)

if not exist "build\Release\packet_pipeline.exe" (
    echo Error: Pipeline executable not found.
    echo Run scripts\run_tests.bat to build the project first.
    exit /b 1
)

build\Release\packet_pipeline.exe "%~1"
exit /b %errorlevel%
