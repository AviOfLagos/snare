@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "BASH_EXE="

if exist "C:\Program Files\Git\bin\bash.exe" set "BASH_EXE=C:\Program Files\Git\bin\bash.exe"
if not defined BASH_EXE if exist "C:\Program Files\Git\usr\bin\bash.exe" set "BASH_EXE=C:\Program Files\Git\usr\bin\bash.exe"
if not defined BASH_EXE if exist "%LOCALAPPDATA%\Programs\Git\bin\bash.exe" set "BASH_EXE=%LOCALAPPDATA%\Programs\Git\bin\bash.exe"

if not defined BASH_EXE (
  for /f "delims=" %%I in ('where bash 2^>nul') do (
    echo %%I | findstr /i "system32" >nul || (set "BASH_EXE=%%I" & goto :found)
  )
)
:found
if not defined BASH_EXE (
  echo Error: Git Bash is required to run snare on Windows. Install Git from https://git-scm.com >&2
  exit /b 1
)

"%BASH_EXE%" "%SCRIPT_DIR%snare" %*
exit /b %ERRORLEVEL%
