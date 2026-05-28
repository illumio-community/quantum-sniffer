#!/usr/bin/env python3
"""
Fix TLS ServerHello entries showing "Unknown" PQ status.
These are ServerHello packets where we failed to extract the key_share group.
Since PQ TLS is still rare in 2026, we default to "No" (classical).
"""
import json
import sys
from pathlib import Path

def main():
    json_file = Path("stinky.json")
    if not json_file.exists():
        print(f"ERROR: {json_file} not found", file=sys.stderr)
        return 1

    # Load data
    with open(json_file, "r") as f:
        data = json.load(f)

    # Find TLS ServerHello with Unknown status
    fixes = 0
    for entry in data:
        if (entry.get("protocol") == "TLS" and
            entry.get("type") == "TLS ServerHello" and
            entry.get("post_quantum_secure") == "Unknown" and
            "selected_cipher" in entry):
            # These are ServerHello with a cipher but no extracted key_share group
            # Standard TLS 1.3 uses classical ECDHE; PQ is still experimental
            entry["post_quantum_secure"] = "No"
            entry["note"] = entry.get("note", "") + " [PQ status inferred: classical crypto]"
            fixes += 1

    print(f"Fixed {fixes} TLS ServerHello entries")

    # Backup original
    backup = json_file.with_suffix(".json.backup")
    if not backup.exists():
        json_file.rename(backup)
        print(f"Original backed up to {backup}")

    # Write updated data
    with open(json_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Updated {json_file}")

    # Show stats
    pq_counts = {}
    for entry in data:
        if entry.get("protocol") == "TLS":
            status = entry.get("post_quantum_secure", "Unknown")
            pq_counts[status] = pq_counts.get(status, 0) + 1

    print("\nTLS post-quantum status counts:")
    for status, count in sorted(pq_counts.items()):
        print(f"  {status}: {count}")

if __name__ == "__main__":
    sys.exit(main() or 0)
