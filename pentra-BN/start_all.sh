#!/bin/bash
set -e
cd "$(dirname "$0")"

# Install dependencies
pip install -r requirements.txt

# Setup database (idempotent)
python setup_postgres.py || true

# Start server in background
python botnet_server.py &
SERVER_PID=$!

# Wait a bit for server to start
sleep 3

# Start bot client
python bot_client.py

# Cleanup
kill $SERVER_PID 