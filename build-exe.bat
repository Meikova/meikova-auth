@echo off
setlocal
cd /d "%~dp0"
echo [MEIKOVA AUTH] Dong goi ung dung Desktop Windows (PyInstaller)...

python -m pip install -q pyinstaller pywebview
pyinstaller --clean --noconfirm meikova_auth.spec

if %ERRORLEVEL% EQU 0 (
    echo [THANH CONG] File thuc thi duoc tao tai: dist\MeikovaAuth.exe
) else (
    echo [THAT BAI] Qua trinh build gap loi.
)
endlocal
