#!/bin/bash
# ==========================================
# ABRDNS Reseller Dashboard - Startup Script
# ==========================================
echo "=== Installing dependencies ==="
pip install -r requirements.txt

echo ""
echo "=== Starting server ==="
python main.py
