#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PID_FILE="$SCRIPT_DIR/acme-server.pid"
LOG_FILE="$SCRIPT_DIR/logs/acme.log"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python"

# Defaults
HOST="0.0.0.0"
PORT=8000
BASE_URL=""
AUTO_ACCEPT=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)   HOST="$2"; shift 2 ;;
        --port)   PORT="$2"; shift 2 ;;
        --base-url) BASE_URL="$2"; shift 2 ;;
        --auto-accept) AUTO_ACCEPT="true"; shift ;;
        -h|--help)
            echo "Usage: ./start.sh [options]"
            echo ""
            echo "Options:"
            echo "  --host HOST         Bind host (default: 0.0.0.0)"
            echo "  --port PORT         Bind port (default: 8000)"
            echo "  --base-url URL      External base URL"
            echo "  --auto-accept       Auto-accept all challenges"
            echo "  -h, --help          Show this help"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Check venv
if [ ! -f "$VENV_PYTHON" ]; then
    echo "Error: venv not found. Run ./install.sh first."
    exit 1
fi

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "ACME Server is already running (PID: $OLD_PID)"
        echo "Stop it first: ./stop.sh"
        exit 1
    else
        rm -f "$PID_FILE"
    fi
fi

# Build environment
export ACME_HOST="$HOST"
export ACME_PORT="$PORT"
[ -n "$BASE_URL" ] && export ACME_BASE_URL="$BASE_URL"
[ -n "$AUTO_ACCEPT" ] && export ACME_AUTO_ACCEPT_CHALLENGES="true"

mkdir -p logs

echo "Starting ACME Server..."
echo "  Host:     $HOST"
echo "  Port:     $PORT"
[ -n "$BASE_URL" ] && echo "  Base URL: $BASE_URL"
[ -n "$AUTO_ACCEPT" ] && echo "  Auto accept challenges: enabled"
echo "  PID file: $PID_FILE"
echo "  Log file: $LOG_FILE"

nohup "$VENV_PYTHON" -m uvicorn app.main:app \
    --host "$HOST" \
    --port "$PORT" \
    --log-level info \
    >> "$LOG_FILE" 2>&1 &

echo $! > "$PID_FILE"

# Wait and verify
sleep 2
PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
    echo "ACME Server started (PID: $PID)"
    echo "Directory: http://${HOST}:${PORT}/directory"
else
    echo "Error: ACME Server failed to start. Check $LOG_FILE"
    rm -f "$PID_FILE"
    exit 1
fi
