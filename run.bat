@echo off
rem FileSorter 2.0 launcher (Windows)
rem Usage: run.bat [folder] [extra options...]
setlocal
set HERE=%~dp0
if "%~1"=="" (
  python "%HERE%file_sorter.py" "%CD%"
) else (
  python "%HERE%file_sorter.py" %*
)
endlocal
