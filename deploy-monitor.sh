#!/bin/bash
set -e

#
# Deploy quantum-sniffer monitoring
#
# Usage:
#   ./deploy-monitor.sh --daily        # Active scanning once per day (self-scan.py)
#   ./deploy-monitor.sh --persistent   # Passive monitoring daemon (persistent-monitor.py)
#

MODE=""
INTERFACE=""
USER_CRON=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --daily)
            MODE="daily"
            shift
            ;;
        --persistent)
            MODE="persistent"
            shift
            ;;
        --interface)
            INTERFACE="$2"
            shift 2
            ;;
        --user-cron)
            USER_CRON=true
            shift
            ;;
        --help)
            cat <<EOF
Deploy quantum-sniffer monitoring in daily or persistent mode.

Usage:
  $0 --daily              Deploy daily active scanning (self-scan.py via cron)
  $0 --persistent         Deploy persistent passive monitoring (daemon via systemd)
  $0 --daily --user-cron  Deploy daily mode for current user (no sudo)

Options:
  --daily         Active scanning mode: run self-scan.py once per day at 2 AM
  --persistent    Passive monitoring mode: continuous traffic analysis daemon
  --interface IF  Network interface for persistent mode (default: auto-detect)
  --user-cron     Install cron for current user instead of system-wide (daily mode only)
  --help          Show this help

Examples:
  # Deploy daily active scanning (system-wide)
  sudo $0 --daily

  # Deploy persistent passive monitoring
  sudo $0 --persistent

  # Deploy daily scanning for current user
  $0 --daily --user-cron

  # Deploy persistent monitoring on specific interface
  sudo $0 --persistent --interface eth0
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run '$0 --help' for usage"
            exit 1
            ;;
    esac
done

# Check mode is specified
if [ -z "$MODE" ]; then
    echo "Error: Must specify --daily or --persistent"
    echo "Run '$0 --help' for usage"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if quantum-sniffer module is available
if ! python3 -c "import quantum_sniffer" 2>/dev/null && \
   ! [ -f "$SCRIPT_DIR/venv/lib/python3.12/site-packages/quantum_sniffer/__init__.py" ] && \
   ! [ -f "$SCRIPT_DIR/venv/lib/python3.11/site-packages/quantum_sniffer/__init__.py" ]; then
    echo "Error: quantum-sniffer module not found"
    echo "Please install with: pip install quantum-sniffer"
    echo "Or run from quantum-sniffer source directory with venv set up"
    exit 1
fi

#
# Daily Mode Deployment
#
if [ "$MODE" = "daily" ]; then
    echo "=== Deploying Daily Active Scanning Mode ==="
    echo

    if [ "$USER_CRON" = true ]; then
        echo "Installing cron for current user: $USER"

        # User cron (no sudo needed)
        CRON_FILE=$(mktemp)
        crontab -l > "$CRON_FILE" 2>/dev/null || true

        # Remove old entry if exists
        sed -i '/quantum-sniffer.*self-scan\.py/d' "$CRON_FILE"

        # Add new entry
        echo "# Quantum-sniffer daily self-scan" >> "$CRON_FILE"
        echo "0 2 * * * $SCRIPT_DIR/self-scan.py 2>/dev/null > \$HOME/.quantum-sniffer-scan.json" >> "$CRON_FILE"

        crontab "$CRON_FILE"
        rm "$CRON_FILE"

        echo "✓ Cron job installed for $USER"
        echo "  Runs at: 2:00 AM daily"
        echo "  Output: \$HOME/.quantum-sniffer-scan.json"
    else
        # System-wide cron (requires sudo)
        if [ "$EUID" -ne 0 ]; then
            echo "Error: System-wide cron requires sudo"
            echo "Run: sudo $0 --daily"
            echo "Or use: $0 --daily --user-cron"
            exit 1
        fi

        # Create log directory
        mkdir -p /var/log/quantum-sniffer
        chmod 755 /var/log/quantum-sniffer

        # Install to /opt
        echo "Installing to /opt/quantum-sniffer..."
        mkdir -p /opt/quantum-sniffer
        cp -r "$SCRIPT_DIR/"* /opt/quantum-sniffer/
        chmod +x /opt/quantum-sniffer/self-scan.py
        chmod +x /opt/quantum-sniffer/discover-external-services.py

        # Install cron
        CRON_FILE="/etc/cron.d/quantum-sniffer-self-scan"
        cat > "$CRON_FILE" <<EOF
# Quantum-sniffer daily self-scan
# Runs active PQC scanning once per day

SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 2 * * * root /opt/quantum-sniffer/self-scan.py 2>/dev/null > /var/log/quantum-sniffer/self-scan.json
EOF
        chmod 644 "$CRON_FILE"

        echo "✓ Daily active scanning deployed"
        echo "  Installed to: /opt/quantum-sniffer/"
        echo "  Cron file: $CRON_FILE"
        echo "  Runs at: 2:00 AM daily"
        echo "  Output: /var/log/quantum-sniffer/self-scan.json"
    fi

    echo
    echo "Daily mode uses ACTIVE SCANNING (self-scan.py):"
    echo "  - Discovers externally-accessible services"
    echo "  - Actively probes each service with quantum-sniffer --probe"
    echo "  - Generates JSON report of PQC support"
    echo "  - Suitable for compliance checking and periodic audits"
    echo

#
# Persistent Mode Deployment
#
elif [ "$MODE" = "persistent" ]; then
    echo "=== Deploying Persistent Passive Monitoring Mode ==="
    echo

    if [ "$EUID" -ne 0 ]; then
        echo "Error: Persistent mode requires sudo (for packet capture)"
        echo "Run: sudo $0 --persistent"
        exit 1
    fi

    # Install to /opt
    echo "Installing to /opt/quantum-sniffer..."
    mkdir -p /opt/quantum-sniffer
    cp -r "$SCRIPT_DIR/"* /opt/quantum-sniffer/
    chmod +x /opt/quantum-sniffer/persistent-monitor.py

    # Create log directory
    mkdir -p /var/log/quantum-sniffer
    chmod 755 /var/log/quantum-sniffer

    # Detect interface if not specified
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip route show default | awk '/default/ {print $5; exit}')
        if [ -z "$INTERFACE" ]; then
            INTERFACE="eth0"
        fi
        echo "Auto-detected interface: $INTERFACE"
    fi

    # Install systemd service
    SERVICE_FILE="/etc/systemd/system/quantum-sniffer-monitor@.service"
    cp "$SCRIPT_DIR/quantum-sniffer-monitor.service" "$SERVICE_FILE"
    chmod 644 "$SERVICE_FILE"

    # Reload systemd
    systemctl daemon-reload

    # Enable and start service
    SERVICE_NAME="quantum-sniffer-monitor@$INTERFACE.service"
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"

    echo "✓ Persistent passive monitoring deployed"
    echo "  Installed to: /opt/quantum-sniffer/"
    echo "  Service: $SERVICE_NAME"
    echo "  Interface: $INTERFACE"
    echo "  Logs: /var/log/quantum-sniffer/"
    echo
    echo "Service status:"
    systemctl status "$SERVICE_NAME" --no-pager -l || true
    echo
    echo "Persistent mode uses PASSIVE MONITORING (persistent-monitor.py):"
    echo "  - Captures live network traffic on $INTERFACE"
    echo "  - Analyzes PQC status of actual connections"
    echo "  - Logs to rolling JSONL files"
    echo "  - Runs continuously as a systemd daemon"
    echo "  - Suitable for real-time monitoring and traffic analysis"
    echo
    echo "Commands:"
    echo "  systemctl status $SERVICE_NAME   # Check status"
    echo "  systemctl stop $SERVICE_NAME     # Stop monitoring"
    echo "  systemctl start $SERVICE_NAME    # Start monitoring"
    echo "  journalctl -u $SERVICE_NAME -f   # View logs"
fi

echo
echo "Deployment complete!"
