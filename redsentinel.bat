@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
py -3.12 "%~dp0run.py" %*

