@echo off
cd /d "%~dp0"
powershell -NoProfile -Command "Copy-Item .data ('backups\' + (Get-Date -Format 'yyyy-MM-dd_HH-mm')) -Recurse"
echo Backup concluido na pasta backups.
pause
