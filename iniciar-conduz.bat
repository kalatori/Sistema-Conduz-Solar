@echo off
cd /d "%~dp0"
start "Conduz Solar ERP" /min cmd /c "node --env-file=.env node_modules/tsx/dist/cli.mjs server.ts"
timeout /t 6 /nobreak >nul
start "" http://localhost:3000
