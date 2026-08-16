#!/usr/bin/env bash
# ControlTrace AI - one-command setup & run
# Usage: ./run.sh   (from inside the ControlTrace-AI project folder)

set -e

# Must be run from inside the ControlTrace-AI folder (where requirements.txt lives)
if [ ! -f "requirements.txt" ]; then
  echo "Error: run this script from inside the ControlTrace-AI folder (requirements.txt not found here)."
  exit 1
fi

# Create the virtual environment if it doesn't exist yet
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

# Activate it
source .venv/bin/activate

# Install/update dependencies
echo "Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Optional: enable the live AI Assistant by exporting ANTHROPIC_API_KEY before running,
# e.g. export ANTHROPIC_API_KEY=sk-ant-...

echo ""
echo "Starting ControlTrace AI..."
echo "Open http://127.0.0.1:8000 in your browser"
echo "Login: admin@controltrace.local / Mente1122"
echo ""

uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
