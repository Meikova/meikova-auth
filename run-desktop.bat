@echo off
setlocal
cd /d "%~dp0"
echo [MEIKOVA AUTH] Khoi chay ung dung Desktop...
python meikova_auth_desktop.py %*
endlocal
