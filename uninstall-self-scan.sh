#!/bin/bash
# Uninstall quantum-sniffer self-scan and remove ALL traces
#
# This script removes:
# - Installation directory
# - Log directory (including all log files)
# - Cron job
# - Logrotate configuration
#
# Usage:
#   sudo ./uninstall-self-scan.sh           # System-wide uninstall
#   ./uninstall-self-scan.sh --user-cron    # User-only uninstall

set -e

USER_MODE=false
FORCE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --user-cron)
            USER_MODE=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--user-cron] [--force]"
            exit 1
            ;;
    esac
done

echo "========================================"
echo "Quantum-Sniffer Self-Scan Uninstall"
echo "========================================"
echo ""

if [ "$USER_MODE" = true ]; then
    echo "Mode: User uninstall"
    INSTALL_DIR="$HOME/.local/share/quantum-sniffer"
    LOG_DIR="$HOME/.local/log/quantum-sniffer"
else
    echo "Mode: System-wide uninstall"
    INSTALL_DIR="/opt/quantum-sniffer"
    LOG_DIR="/var/log/quantum-sniffer"

    if [ "$EUID" -ne 0 ] && [ "$FORCE" = false ]; then
        echo ""
        echo "ERROR: System-wide uninstall requires sudo"
        echo ""
        echo "Run with: sudo $0"
        echo "Or for user uninstall: $0 --user-cron"
        exit 1
    fi
fi

echo ""

# Check what exists
FOUND_SOMETHING=false

if [ -d "$INSTALL_DIR" ]; then
    FOUND_SOMETHING=true
    echo "Found: $INSTALL_DIR"
fi

if [ -d "$LOG_DIR" ]; then
    FOUND_SOMETHING=true
    echo "Found: $LOG_DIR"

    # Count log files
    LOG_COUNT=$(find "$LOG_DIR" -type f 2>/dev/null | wc -l)
    if [ "$LOG_COUNT" -gt 0 ]; then
        echo "  Contains $LOG_COUNT log file(s)"
    fi
fi

if [ "$USER_MODE" = false ]; then
    if [ -f "/etc/cron.d/quantum-sniffer-self-scan" ]; then
        FOUND_SOMETHING=true
        echo "Found: /etc/cron.d/quantum-sniffer-self-scan"
    fi

    if [ -f "/etc/logrotate.d/quantum-sniffer" ]; then
        FOUND_SOMETHING=true
        echo "Found: /etc/logrotate.d/quantum-sniffer"
    fi
else
    # Check user crontab
    if crontab -l 2>/dev/null | grep -q "quantum-sniffer\|self-scan.py"; then
        FOUND_SOMETHING=true
        echo "Found: Crontab entry for quantum-sniffer"
    fi
fi

if [ "$FOUND_SOMETHING" = false ]; then
    echo ""
    echo "Nothing to uninstall - quantum-sniffer self-scan not found"
    exit 0
fi

# Warn about data loss
echo ""
echo "⚠️  WARNING: This will PERMANENTLY DELETE:"
echo ""
if [ -d "$INSTALL_DIR" ]; then
    echo "  - Installation: $INSTALL_DIR"
fi
if [ -d "$LOG_DIR" ]; then
    echo "  - All log files: $LOG_DIR"
fi
if [ "$USER_MODE" = false ]; then
    if [ -f "/etc/cron.d/quantum-sniffer-self-scan" ]; then
        echo "  - Cron job: /etc/cron.d/quantum-sniffer-self-scan"
    fi
    if [ -f "/etc/logrotate.d/quantum-sniffer" ]; then
        echo "  - Logrotate config: /etc/logrotate.d/quantum-sniffer"
    fi
else
    if crontab -l 2>/dev/null | grep -q "quantum-sniffer\|self-scan.py"; then
        echo "  - Crontab entry"
    fi
fi
echo ""
echo "This operation CANNOT be undone."
echo ""

# Require confirmation unless --force
if [ "$FORCE" = false ]; then
    read -p "Type 'yes' to proceed: " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Aborted."
        exit 0
    fi
    echo ""
fi

# Step 1: Stop any running scans
echo "[1/5] Stopping any running scans..."
KILLED=false

if [ "$USER_MODE" = false ]; then
    # Kill system processes
    if pgrep -f "/opt/quantum-sniffer/self-scan.py" > /dev/null; then
        pkill -f "/opt/quantum-sniffer/self-scan.py" 2>/dev/null || true
        KILLED=true
    fi
else
    # Kill user processes
    if pgrep -u "$USER" -f "self-scan.py" > /dev/null; then
        pkill -u "$USER" -f "self-scan.py" 2>/dev/null || true
        KILLED=true
    fi
fi

if [ "$KILLED" = true ]; then
    echo "  ✓ Stopped running scan processes"
    sleep 2
else
    echo "  No running scans found"
fi

# Step 2: Remove cron job
echo ""
echo "[2/5] Removing cron job..."

if [ "$USER_MODE" = false ]; then
    # System cron
    if [ -f "/etc/cron.d/quantum-sniffer-self-scan" ]; then
        rm -f "/etc/cron.d/quantum-sniffer-self-scan"
        echo "  ✓ Removed /etc/cron.d/quantum-sniffer-self-scan"
    else
        echo "  Cron job not found (already removed)"
    fi
else
    # User cron
    if crontab -l 2>/dev/null | grep -q "quantum-sniffer\|self-scan.py"; then
        # Remove lines containing quantum-sniffer or self-scan.py
        crontab -l 2>/dev/null | grep -v "quantum-sniffer\|self-scan.py" | crontab - || true
        echo "  ✓ Removed crontab entry"
    else
        echo "  Crontab entry not found (already removed)"
    fi
fi

# Step 3: Remove logrotate config
if [ "$USER_MODE" = false ]; then
    echo ""
    echo "[3/5] Removing logrotate config..."
    if [ -f "/etc/logrotate.d/quantum-sniffer" ]; then
        rm -f "/etc/logrotate.d/quantum-sniffer"
        echo "  ✓ Removed /etc/logrotate.d/quantum-sniffer"
    else
        echo "  Logrotate config not found (already removed)"
    fi
else
    echo ""
    echo "[3/5] Skipping logrotate (user mode)"
fi

# Step 4: Remove log directory and all log files
echo ""
echo "[4/5] Removing log directory..."

if [ -d "$LOG_DIR" ]; then
    # Show what will be deleted
    LOG_COUNT=$(find "$LOG_DIR" -type f 2>/dev/null | wc -l)
    LOG_SIZE=$(du -sh "$LOG_DIR" 2>/dev/null | cut -f1)

    echo "  Deleting $LOG_COUNT file(s) ($LOG_SIZE total)"

    rm -rf "$LOG_DIR"

    if [ -d "$LOG_DIR" ]; then
        echo "  ⚠️  WARNING: Failed to remove $LOG_DIR"
    else
        echo "  ✓ Removed $LOG_DIR"
    fi
else
    echo "  Log directory not found (already removed)"
fi

# Step 5: Remove installation directory
echo ""
echo "[5/5] Removing installation directory..."

if [ -d "$INSTALL_DIR" ]; then
    INSTALL_SIZE=$(du -sh "$INSTALL_DIR" 2>/dev/null | cut -f1)

    echo "  Deleting installation ($INSTALL_SIZE)"

    rm -rf "$INSTALL_DIR"

    if [ -d "$INSTALL_DIR" ]; then
        echo "  ⚠️  WARNING: Failed to remove $INSTALL_DIR"
    else
        echo "  ✓ Removed $INSTALL_DIR"
    fi
else
    echo "  Installation directory not found (already removed)"
fi

# Verify removal
echo ""
echo "========================================"
echo "Verification"
echo "========================================"
echo ""

ALL_CLEAN=true

if [ -d "$INSTALL_DIR" ]; then
    echo "⚠️  $INSTALL_DIR still exists"
    ALL_CLEAN=false
fi

if [ -d "$LOG_DIR" ]; then
    echo "⚠️  $LOG_DIR still exists"
    ALL_CLEAN=false
fi

if [ "$USER_MODE" = false ]; then
    if [ -f "/etc/cron.d/quantum-sniffer-self-scan" ]; then
        echo "⚠️  /etc/cron.d/quantum-sniffer-self-scan still exists"
        ALL_CLEAN=false
    fi

    if [ -f "/etc/logrotate.d/quantum-sniffer" ]; then
        echo "⚠️  /etc/logrotate.d/quantum-sniffer still exists"
        ALL_CLEAN=false
    fi
else
    if crontab -l 2>/dev/null | grep -q "quantum-sniffer\|self-scan.py"; then
        echo "⚠️  Crontab entry still exists"
        ALL_CLEAN=false
    fi
fi

if [ "$ALL_CLEAN" = true ]; then
    echo "✓ All traces removed successfully"
    echo ""
    echo "Quantum-sniffer self-scan has been completely uninstalled."
else
    echo ""
    echo "⚠️  Some items could not be removed"
    echo "You may need to remove them manually"
fi

echo ""
echo "========================================"
echo "Uninstall Complete"
echo "========================================"
echo ""

# Check for any remaining references
echo "Scanning for any remaining references..."
FOUND_REFS=false

# Check for running processes
if pgrep -f "quantum-sniffer.*self-scan" > /dev/null 2>&1; then
    echo "⚠️  Found running quantum-sniffer processes"
    FOUND_REFS=true
fi

# Check for any remaining files in /tmp
if ls /tmp/quantum-sniffer-* 2>/dev/null | grep -q .; then
    echo "⚠️  Found temporary files in /tmp/quantum-sniffer-*"
    echo "    These are safe to delete: rm -rf /tmp/quantum-sniffer-*"
    FOUND_REFS=true
fi

# Check user's home directory
if [ "$USER_MODE" = false ] && [ -n "$SUDO_USER" ]; then
    USER_HOME=$(eval echo ~$SUDO_USER)
    if [ -d "$USER_HOME/quantum-sniffer" ]; then
        echo "ℹ️  Found source directory: $USER_HOME/quantum-sniffer"
        echo "    This is the source code (not removed by this script)"
        FOUND_REFS=true
    fi
fi

if [ "$FOUND_REFS" = false ]; then
    echo "✓ No remaining references found"
fi

echo ""
