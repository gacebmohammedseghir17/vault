@echo off
REM This is a test batch file for YARA detection
echo Starting suspicious activity simulation
cmd.exe /c "echo This should trigger YARA detection"
reg add HKLM\Software\Test /v TestValue /t REG_SZ /d "TestData" /f
echo Suspicious script execution completed