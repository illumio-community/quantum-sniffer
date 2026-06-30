#!/bin/bash
# Scan 10.1.0.0/23 network for all testable encrypted protocols

set -e  # Exit on error

# Configuration
NETWORK="10.1.0.0/23"
PORTS="22,25,110,143,443,500,587,636,853,989,990,992,993,995,3389,4500,5061,8443"
WORKERS=50
TIMEOUT=3
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="$(dirname "$0")/scans"
OUTPUT_BASE="scan-${TIMESTAMP}"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "=========================================="
echo "Quantum-Sniffer Network Scan"
echo "=========================================="
echo "Network:  $NETWORK"
echo "Ports:    $PORTS"
echo "Workers:  $WORKERS"
echo "Timeout:  ${TIMEOUT}s"
echo "Output:   $OUTPUT_DIR/$OUTPUT_BASE.*"
echo "=========================================="
echo ""

# Run the scan
echo "Starting scan at $(date)..."
echo ""

quantum-sniffer --probe "$NETWORK" \
  --ports "$PORTS" \
  --output-json "$OUTPUT_DIR/${OUTPUT_BASE}.json" \
  --output-markdown "$OUTPUT_DIR/${OUTPUT_BASE}.md" \
  --workers "$WORKERS" \
  --timeout "$TIMEOUT"

echo ""
echo "=========================================="
echo "Scan complete at $(date)"
echo "=========================================="
echo ""

# Convert markdown to HTML if pandoc is available
if command -v pandoc &> /dev/null; then
    echo "Converting markdown to HTML..."
    pandoc --metadata title="scan" -s "$OUTPUT_DIR/${OUTPUT_BASE}.md" -o "$OUTPUT_DIR/${OUTPUT_BASE}.html"
    echo "HTML report: $OUTPUT_DIR/${OUTPUT_BASE}.html"
    echo ""
fi

# Display summary from JSON
if command -v jq &> /dev/null; then
    echo "=========================================="
    echo "Scan Summary"
    echo "=========================================="
    jq -r '.summary |
        "Total Ports Scanned: \(.total_ports_scanned)\n" +
        "Open Ports: \(.open_ports)\n" +
        "Closed Ports: \(.closed_ports)\n" +
        "Timeout Ports: \(.timeout_ports)\n" +
        "PQ-Capable: \(.pq_capable_ports)/\(.open_ports)"' \
        "$OUTPUT_DIR/${OUTPUT_BASE}.json"
    echo ""
fi

echo "=========================================="
echo "Output Files:"
echo "=========================================="
ls -lh "$OUTPUT_DIR/${OUTPUT_BASE}."*
echo ""

echo "To view results:"
echo "  JSON:     jq . $OUTPUT_DIR/${OUTPUT_BASE}.json"
echo "  Markdown: less $OUTPUT_DIR/${OUTPUT_BASE}.md"
if [ -f "$OUTPUT_DIR/${OUTPUT_BASE}.html" ]; then
    echo "  HTML:     firefox $OUTPUT_DIR/${OUTPUT_BASE}.html"
fi
echo ""
