
@echo off
setlocal

cd /d "%~dp0.."

echo === Building project ===
cmake --build build --config Release
if errorlevel 1 goto :failed

echo.
echo === Header tests ===
build\Release\test_headers.exe
if errorlevel 1 goto :failed

echo.
echo === PCAP reader tests ===
build\Release\test_pcap_reader.exe
if errorlevel 1 goto :failed

echo.
echo === ACL tests ===
build\Release\test_acl.exe
if errorlevel 1 goto :failed

echo.
echo === Routing tests ===
build\Release\test_routing.exe
if errorlevel 1 goto :failed

echo.
echo === Pipeline integration tests ===
build\Release\test_pipeline.exe
if errorlevel 1 goto :failed

echo.
echo ALL TESTS PASSED
exit /b 0

:failed
echo.
echo BUILD OR TEST FAILED
exit /b 1
