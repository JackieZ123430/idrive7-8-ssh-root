@echo off
REM Build the MGU iDrive SSH Tool into a Windows .exe (one-folder app).
REM Run this from a normal Command Prompt in the project root, with Python on PATH.
setlocal

echo === Installing dependencies (cryptography, pyinstaller) ===
python -m pip install --upgrade pip || goto :err
python -m pip install -r requirements.txt pyinstaller || goto :err

echo === Building with PyInstaller ===
python -m PyInstaller --noconfirm MGU-SSH.spec || goto :err

echo === Copying runtime files next to the exe ===
xcopy /E /I /Y data\assets "dist\MGU-SSH\data\assets" || goto :err
copy /Y sshd-always-on.sh "dist\MGU-SSH\" >nul || goto :err

echo.
echo Done.  Launch:  dist\MGU-SSH\MGU-SSH.exe
echo (Keep the whole dist\MGU-SSH folder together; per-car keys are saved in
echo  dist\MGU-SSH\data\enrollments\.)
goto :eof

:err
echo.
echo BUILD FAILED (see the error above).
exit /b 1
