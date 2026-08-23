@echo off
setlocal
where pwsh >nul 2>&1
if not errorlevel 1 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0启动智安哨.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0启动智安哨.ps1"
)
if errorlevel 1 (
  echo.
  echo 智安哨启动失败，请把上面的错误信息发给开发者排查。
  pause
)
