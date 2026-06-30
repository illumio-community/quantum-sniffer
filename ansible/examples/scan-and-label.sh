#!/bin/bash
# Scan hosts and label in Illumio PCE

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "========================================"
echo "Scan and Label Workflow"
echo "========================================"
echo ""

# Check Illumio credentials
if [ -z "$ILLUMIO_PCE_HOST" ] || [ -z "$ILLUMIO_API_KEY" ]; then
  echo "ERROR: Illumio credentials not set"
  echo ""
  echo "Set these environment variables:"
  echo "  export ILLUMIO_PCE_HOST=pce.example.com"
  echo "  export ILLUMIO_API_KEY=api_123..."
  echo "  export ILLUMIO_API_SECRET=123..."
  exit 1
fi

echo "Using Illumio PCE: $ILLUMIO_PCE_HOST"
echo ""

cd "$ANSIBLE_DIR"

# Step 1: Scan hosts
echo "Step 1: Scanning hosts..."
echo ""
ansible-playbook -i inventory.ini run-quantum-sniffer.yml \
  -l production \
  -e "scan_ports=22,443" \
  -f 5

echo ""
echo "Step 2: Labeling workloads in Illumio..."
echo ""

# Step 2: Label in Illumio based on scan results
for json_file in "$ANSIBLE_DIR/results"/*.json; do
  if [ -f "$json_file" ]; then
    hostname=$(basename "$json_file" | cut -d'-' -f1)

    # Extract IP and PQ status from scan results
    ip=$(jq -r '.results[0].target_ip' "$json_file" 2>/dev/null || echo "")

    if [ -n "$ip" ] && [ "$ip" != "null" ]; then
      echo "Labeling $hostname ($ip)..."

      # Use quantum-sniffer to label (it will determine PQ status)
      quantum-sniffer --probe "$ip" --ports 22,443 --illumio-label "$ip" 2>&1 | grep -E "(✓|ERROR)" || true
    fi
  fi
done

echo ""
echo "Step 3: Viewing summary..."
echo ""
quantum-sniffer --illumio-summary

echo ""
echo "========================================"
echo "Workflow Complete"
echo "========================================"
