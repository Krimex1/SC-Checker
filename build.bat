@echo off
setlocal

cd /d "%~dp0"

set CGO_ENABLED=1
set GOOS=windows
set GOARCH=amd64

if "%1"=="console" goto console
if "%1"=="run" goto run

echo [build] target:  %GOOS%/%GOARCH%
echo [build] flags:   -ldflags="-s -w -H windowsgui" -trimpath -buildvcs=false
echo [build] output:  sc-checker.exe
echo.

go build -ldflags="-s -w -H windowsgui" -trimpath -buildvcs=false -o sc-checker.exe .\cmd\sc-checker
if errorlevel 1 goto err
goto done

:run
go build -ldflags="-s -w -H windowsgui" -o sc-checker.exe .\cmd\sc-checker
if errorlevel 1 goto err
sc-checker.exe
exit /b 0

:console
echo [build] console build (with stdout/stderr) - for debugging
go build -ldflags="-s -w" -trimpath -buildvcs=false -o sc-checker.exe .\cmd\sc-checker
if errorlevel 1 goto err
sc-checker.exe
exit /b 0

:done
powershell -NoProfile -Command "$f = Get-Item sc-checker.exe; '{0:N2} MB ({1} KB)' -f ($f.Length/1MB), [int]($f.Length/1024)"
echo.
echo [tip] for runtime RAM cap set before launching:
echo       set GOMEMLIMIT=256MiB
echo       set GOGC=50
echo.
echo [tip] for a console-attached build use: build.bat console
exit /b 0

:err
echo.
echo [build] FAILED - check that MinGW (gcc) is on PATH and fyne deps are present.
exit /b 1
