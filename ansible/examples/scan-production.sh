#!/bin/bash
# Scan all production hosts with quantum-sniffer

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "========================================"
echo "Quantum-Sniffer Production Scan"
echo "========================================"
echo ""

cd "$ANSIBLE_DIR"

# Scan production hosts
ansible-playbook -i inventory.ini run-quantum-sniffer.yml \
  -l production \
  -e "scan_ports=22,443,3389,5432,3306" \
  -e "scan_timeout=5" \
  -e "scan_workers=10" \
  -f 5

echo ""
echo "========================================"
echo "Scan Complete"
echo "========================================"
echo ""

# Show results
echo "Results:"
ls -lh "$ANSIBLE_DIR/results/"

echo ""
echo "View results with:"
echo "  less $ANSIBLE_DIR/results/<hostname>-<date>-scan.md"
echo "  jq . $ANSIBLE_DIR/results/<hostname>-<date>-scan.json"
