#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== ACME Server Install ==="

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Python version: $PYTHON_VERSION"

# Create venv
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Install dependencies
echo "Installing dependencies..."
./venv/bin/pip install --upgrade pip -q
./venv/bin/pip install -r requirements.txt -q

# Create directories
mkdir -p logs ca certs

# Generate CA certificate
echo "Generating CA certificate..."
./venv/bin/python -c "from app.crypto import ensure_ca; ensure_ca(); print('CA certificate generated')"

# Print config
echo ""
echo "=== Install Complete ==="
echo "  Python:     $(./venv/bin/python --version)"
echo "  CA cert:    ca/ca_cert.pem"
echo "  CA key:     ca/ca_key.pem"
echo "  Log dir:    logs/"
echo ""
echo "Usage:"
echo "  ./start.sh                    # Start with defaults"
echo "  ./start.sh --port 443         # Start on port 443"
echo "  ./start.sh --base-url https://acme.example.com"
echo "  ./stop.sh                     # Stop server"
