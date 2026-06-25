@echo off
setlocal

if not "%AUGENMASS_BIN%"=="" (
  "%AUGENMASS_BIN%" %*
  exit /b %ERRORLEVEL%
)

set "SCRIPT_DIR=%~dp0"
set "BIN=%SCRIPT_DIR%x86_64-pc-windows-msvc\augenmass.exe"

if not exist "%BIN%" (
  echo Missing Augenmass binary: %BIN% 1>&2
  echo Install a native release archive or rebuild the plugin bundle, then set AUGENMASS_BIN if needed. 1>&2
  exit /b 127
)

"%BIN%" %*
set "STATUS=%ERRORLEVEL%"

if "%STATUS%"=="126" (
  echo Augenmass could not run the selected binary. 1>&2
  echo These bundled binaries may not be code-signed yet. Verify the release/checksum first. 1>&2
  echo Then right-click augenmass.exe -^> Properties -^> Unblock, or run: Unblock-File .\augenmass.exe 1>&2
)

exit /b %STATUS%
