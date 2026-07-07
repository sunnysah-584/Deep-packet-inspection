@echo off
title Deep Packet Inspection System Builder
echo ================================================================
echo       DEEP PACKET INSPECTION (DPI) SYSTEM - BUILD ENGINE
echo ================================================================
echo.

:: Ensure bin directory exists
if not exist bin mkdir bin

echo [1/2] Compiling source code dependencies...
echo Running: javac -d bin -cp "lib/*" -sourcepath src src\com\cyber\dpi\App.java
javac -d bin -cp "lib/*" -sourcepath src src\com\cyber\dpi\App.java

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Compilation failed! Please check Java errors above.
    echo.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [2/2] Launching Dashboard Swing Application...
echo Running: java -cp "bin;lib/*" com.cyber.dpi.App
java -cp "bin;lib/*" com.cyber.dpi.App

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Application crashed or terminated with error code %ERRORLEVEL%.
)
echo.
echo ================================================================
echo       BUILD ENGINE TERMINATED
echo ================================================================
pause
