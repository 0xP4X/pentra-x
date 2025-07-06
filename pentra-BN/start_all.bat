@echo off
cd /d %~dp0

REM Install dependencies
pip install -r requirements.txt

REM Setup database (idempotent)
python setup_postgres.py

REM Start server in new window
start "C2 Server" cmd /c "python botnet_server.py"

REM Wait for server to start
ping 127.0.0.1 -n 5 > nul

REM Start bot client
python bot_client.py

REM Optionally, pause at the end
pause 