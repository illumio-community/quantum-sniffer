#!/bin/bash
# Deploy quantum-sniffer self-scan for daily automated execution
#
# This script:
# 1. Installs quantum-sniffer (if not already installed)
# 2. Tests the self-scan functionality
# 3. Sets up daily cron job
# 4. Creates log rotation
#
# Usage:
#   sudo ./deploy-self-scan.sh
#   or
#   ./deploy-self-scan.sh --user-cron  # Run as regular user (no sudo)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/quantum-sniffer"
LOG_DIR="/var/log/quantum-sniffer"
LOG_FILE="$LOG_DIR/self-scan.json"
USER_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --user-cron)
            USER_MODE=true
            INSTALL_DIR="$HOME/.local/share/quantum-sniffer"
            LOG_DIR="$HOME/.local/log/quantum-sniffer"
            LOG_FILE="$LOG_DIR/self-scan.json"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--user-cron]"
            exit 1
            ;;
    esac
done

echo "========================================"
echo "Quantum-Sniffer Self-Scan Deployment"
echo "========================================"
echo ""

if [ "$USER_MODE" = true ]; then
    echo "Mode: User cron (no sudo required)"
    echo "Install dir: $INSTALL_DIR"
    echo "Log dir: $LOG_DIR"
else
    echo "Mode: System-wide (requires sudo)"
    echo "Install dir: $INSTALL_DIR"
    echo "Log dir: $LOG_DIR"

    if [ "$EUID" -ne 0 ]; then
        echo ""
        echo "ERROR: This script must be run with sudo for system-wide installation"
        echo ""
        echo "Options:"
        echo "  1. Run with sudo: sudo $0"
        echo "  2. User install:  $0 --user-cron"
        exit 1
    fi
fi

echo ""

# Step 1: Check Python
echo "[1/6] Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is required but not installed"
    echo "Install with: sudo apt install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "  Found: $PYTHON_VERSION"

# Step 2: Install quantum-sniffer
echo ""
echo "[2/6] Installing quantum-sniffer..."

if command -v quantum-sniffer &> /dev/null; then
    echo "  Already installed: $(quantum-sniffer --help | head -1 || echo 'quantum-sniffer')"
elif python3 -m quantum_sniffer --help &> /dev/null; then
    echo "  Already installed (as module)"
else
    echo "  Installing from source..."
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"

    # Create venv and install
    cd "$INSTALL_DIR"
    python3 -m venv venv
    venv/bin/pip install --upgrade pip > /dev/null
    venv/bin/pip install scapy cryptography python-dotenv > /dev/null

    echo "  Installed to $INSTALL_DIR"
fi

# Step 3: Create log directory
echo ""
echo "[3/6] Creating log directory..."
mkdir -p "$LOG_DIR"
if [ "$USER_MODE" = false ]; then
    chmod 755 "$LOG_DIR"
fi
echo "  Created: $LOG_DIR"

# Step 4: Test self-scan
echo ""
echo "[4/6] Testing self-scan..."
TEST_OUTPUT=$(mktemp)

if [ -f "$INSTALL_DIR/self-scan.py" ]; then
    SELF_SCAN_SCRIPT="$INSTALL_DIR/self-scan.py"
else
    SELF_SCAN_SCRIPT="$SCRIPT_DIR/self-scan.py"
fi

if "$SELF_SCAN_SCRIPT" > "$TEST_OUTPUT" 2>&1; then
    echo "  ✓ Self-scan test successful"

    # Check if JSON is valid
    if jq empty "$TEST_OUTPUT" 2>/dev/null; then
        echo "  ✓ JSON output valid"

        # Show summary
        HOSTNAME=$(jq -r '.scan_info.hostname' "$TEST_OUTPUT" 2>/dev/null || echo "unknown")
        PORTS=$(jq -r '.summary.total_ports_scanned' "$TEST_OUTPUT" 2>/dev/null || echo "0")
        PQ_PCT=$(jq -r '.summary.pq_percentage' "$TEST_OUTPUT" 2>/dev/null || echo "0")

        echo "  Hostname: $HOSTNAME"
        echo "  Ports scanned: $PORTS"
        echo "  PQ-capable: $PQ_PCT%"
    else
        echo "  ⚠️  Warning: JSON output may be invalid"
    fi
else
    echo "  ⚠️  Warning: Self-scan test failed (check output)"
fi

rm -f "$TEST_OUTPUT"

# Step 5: Set up cron job
echo ""
echo "[5/6] Setting up daily cron job..."

CRON_CMD="$SELF_SCAN_SCRIPT > $LOG_FILE 2>&1"
CRON_SCHEDULE="0 2 * * *"  # 2 AM daily
CRON_LINE="$CRON_SCHEDULE $CRON_CMD"

if [ "$USER_MODE" = true ]; then
    # User cron
    CURRENT_CRONTAB=$(crontab -l 2>/dev/null || true)

    if echo "$CURRENT_CRONTAB" | grep -q "$SELF_SCAN_SCRIPT"; then
        echo "  Cron job already exists (skipping)"
    else
        (crontab -l 2>/dev/null || true; echo "$CRON_LINE") | crontab -
        echo "  ✓ Added to user crontab"
        echo "  Schedule: Daily at 2:00 AM"
    fi
else
    # System cron
    CRON_FILE="/etc/cron.d/quantum-sniffer-self-scan"

    cat > "$CRON_FILE" <<EOF
# Quantum-Sniffer Daily Self-Scan
# Scans external services for post-quantum crypto support
# Results: $LOG_FILE

SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Run at 2 AM daily
$CRON_SCHEDULE root $CRON_CMD
EOF

    chmod 644 "$CRON_FILE"
    echo "  ✓ Created $CRON_FILE"
    echo "  Schedule: Daily at 2:00 AM"
fi

# Step 6: Set up log rotation
echo ""
echo "[6/6] Setting up log rotation..."

if [ "$USER_MODE" = true ]; then
    echo "  Skipped (user mode - manage logs manually)"
    echo "  Log file: $LOG_FILE"
    echo "  Tip: Use logrotate or clean up periodically"
else
    LOGROTATE_FILE="/etc/logrotate.d/quantum-sniffer"

    cat > "$LOGROTATE_FILE" <<EOF
$LOG_FILE {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF

    chmod 644 "$LOGROTATE_FILE"
    echo "  ✓ Created $LOGROTATE_FILE"
    echo "  Retention: 30 days (compressed)"
fi

# Summary
echo ""
echo "========================================"
echo "Deployment Complete"
echo "========================================"
echo ""
echo "Configuration:"
echo "  Script: $SELF_SCAN_SCRIPT"
echo "  Log:    $LOG_FILE"
echo "  Cron:   Daily at 2:00 AM"
echo ""
echo "Commands:"
echo "  # Run manually"
echo "  $SELF_SCAN_SCRIPT"
echo ""
echo "  # View latest results"
echo "  cat $LOG_FILE"
echo ""
echo "  # View summary"
echo "  jq '.summary' $LOG_FILE"
echo ""
echo "  # View PQ status of each port"
echo "  jq '.scan_results.results[] | {port: .target_port, status: .status, pq: .post_quantum_secure}' $LOG_FILE"
echo ""

if [ "$USER_MODE" = true ]; then
    echo "  # View cron jobs"
    echo "  crontab -l | grep quantum-sniffer"
else
    echo "  # View cron job"
    echo "  cat /etc/cron.d/quantum-sniffer-self-scan"
    echo ""
    echo "  # View logs"
    echo "  tail -f /var/log/cron  # Watch for cron execution"
fi

echo ""
echo "Next scan: Tomorrow at 2:00 AM"
echo ""
