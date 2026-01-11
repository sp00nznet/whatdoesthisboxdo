#!/bin/bash
#
# Setup script for What Does This Box Do
# Creates virtual environment and installs dependencies
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"

echo "================================================"
echo "  What Does This Box Do - Setup"
echo "================================================"
echo

# Check Python version
PYTHON_CMD=""
for cmd in python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "$cmd" &> /dev/null; then
        PYTHON_CMD="$cmd"
        break
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "ERROR: Python 3.8+ is required but not found."
    echo "Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Found Python $PYTHON_VERSION ($PYTHON_CMD)"

# Check if venv module is available
if ! $PYTHON_CMD -c "import venv" 2>/dev/null; then
    echo
    echo "ERROR: Python venv module not found."
    echo
    echo "On Debian/Ubuntu, install it with:"
    echo "  sudo apt install python${PYTHON_VERSION}-venv"
    echo
    echo "On RHEL/CentOS/Fedora:"
    echo "  sudo dnf install python3-virtualenv"
    echo
    exit 1
fi

# Create virtual environment
if [ -d "$VENV_DIR" ]; then
    echo
    read -p "Virtual environment already exists. Recreate it? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing virtual environment..."
        rm -rf "$VENV_DIR"
    else
        echo "Using existing virtual environment."
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    echo
    echo "Creating virtual environment..."
    $PYTHON_CMD -m venv "$VENV_DIR"
fi

# Activate and install
echo
echo "Installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$SCRIPT_DIR/requirements.txt"

echo
echo "================================================"
echo "  Setup Complete!"
echo "================================================"
echo
echo "To activate the virtual environment, run:"
echo "  source venv/bin/activate"
echo
echo "Then you can use the analyzer:"
echo "  python3 analyzer.py -H <hostname> -u <user> -k ~/.ssh/id_rsa"
echo
echo "Or with password authentication:"
echo "  python3 analyzer.py -H <hostname> -u <user> --password"
echo
