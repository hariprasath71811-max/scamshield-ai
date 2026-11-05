@echo off
setlocal
cd /d "%~dp0"

where javac >nul 2>nul
if errorlevel 1 (
  echo [ScamShield] Java 11+ is required. Install a JDK and try again.
  exit /b 1
)

if not exist out mkdir out

echo [ScamShield] Compiling...
javac --release 11 -d out src\Main.java
if errorlevel 1 (
  echo [ScamShield] Compilation failed.
  exit /b 1
)

echo [ScamShield] Starting on http://localhost:8080 ...
java --add-modules jdk.httpserver -cp out Main %*
