@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

REM SQLMap WebUI Burp Extension - File Synchronization Script
REM This script synchronizes shared files between legacy-api and montoya-api modules

echo ============================================
echo SQLMap WebUI Burp Extension Sync Script
echo ============================================
echo.

set "LEGACY_DIR=src\burpEx\legacy-api\src\main\java\com\sqlmapwebui\burp"
set "MONTOYA_DIR=src\burpEx\montoya-api\src\main\java\com\sqlmapwebui\burp"
set "BACKUP_DIR=src\burpEx\backup_%date:~0,4%%date:~5,2%%date:~8,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "BACKUP_DIR=!BACKUP_DIR: =0!"

echo Source: %LEGACY_DIR%
echo Target: %MONTOYA_DIR%
echo.

REM Create backup of montoya-api
echo Creating backup of montoya-api...
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"
xcopy /E /I /Y "%MONTOYA_DIR%\*" "%BACKUP_DIR%\burp" >nul 2>&1
echo Backup created: %BACKUP_DIR%
echo.

REM List of files to sync (shared between both modules)
echo Synchronizing shared files...

REM Model classes
call :sync_file "ScanConfig.java"
call :sync_file "PresetConfig.java"
call :sync_file "ParseResult.java"
call :sync_file "ParamMeta.java"

REM Utility classes
call :sync_file "ScanConfigParser.java"
call :sync_file "BinaryContentDetector.java"
call :sync_file "RequestDeduplicator.java"
call :sync_file "ApiClient.java"
call :sync_file "SqlmapApiClient.java"
call :sync_file "PresetConfigDatabase.java"
call :sync_file "ConfigManager.java"

REM UI Tab
call :sync_file "SqlmapUITab.java"

REM Panel classes
call :sync_dir "panels"

REM Dialog classes  
call :sync_dir "dialogs"

echo.
echo ============================================
echo Synchronization completed!
echo ============================================
echo.
echo Note: The following files are API-specific and NOT synced:
echo   - BurpExtender.java (Legacy entry point)
echo   - SqlmapWebUIExtension.java (Montoya entry point)
echo   - SqlmapContextMenuProvider.java (Montoya-specific)
echo   - HttpRequestUtils.java (Montoya-specific)
echo   - util\PayloadBuilder.java (Montoya-specific)
echo   - util\LoggerUtil.java (Montoya-specific)
echo.
pause
goto :eof

REM Function to sync a single file
:sync_file
set "FILE_NAME=%~1"
set "SOURCE=%LEGACY_DIR%\%FILE_NAME%"
set "TARGET=%MONTOYA_DIR%\%FILE_NAME%"

if exist "%SOURCE%" (
    if exist "%TARGET%" (
        copy /Y "%SOURCE%" "%TARGET%" >nul
        echo [OK] Synced: %FILE_NAME%
    ) else (
        echo [SKIP] Target not found: %FILE_NAME%
    )
) else (
    echo [SKIP] Source not found: %FILE_NAME%
)
goto :eof

REM Function to sync a directory
:sync_dir
set "DIR_NAME=%~1"
set "SOURCE=%LEGACY_DIR%\%DIR_NAME%"
set "TARGET=%MONTOYA_DIR%\%DIR_NAME%"

if exist "%SOURCE%" (
    if exist "%TARGET%" (
        xcopy /E /Y "%SOURCE%\*" "%TARGET%\" >nul 2>&1
        echo [OK] Synced directory: %DIR_NAME%
    ) else (
        echo [SKIP] Target directory not found: %DIR_NAME%
    )
) else (
    echo [SKIP] Source directory not found: %DIR_NAME%
)
goto :eof
