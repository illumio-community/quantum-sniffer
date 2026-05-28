#!/usr/bin/env python3
"""
Fix post_quantum_secure status in existing stinky.json files.

Updates QUIC entries from "Unknown" to "No" (classical crypto) when
decryption failed or no PQ groups were detected.
"""

import json
import sys
from pathlib import Path

def fix_pq_status(data):
    """Fix post_quantum_secure field for each entry."""
    fixed_count = 0
    for entry in data:
        if entry.get("post_quantum_secure") == "Unknown":
            protocol = entry.get("protocol")

            # QUIC without PQ indicators should be "No" (classical crypto)
            if protocol == "QUIC":
                # Check if it has supported_groups (successful decryption)
                has_groups = bool(entry.get("supported_groups"))
                has_pq = False

                if has_groups:
                    # Check if any groups are PQ
                    for group in entry.get("supported_groups", []):
                        g = group.lower()
                        if any(pq in g for pq in ["kyber", "mlkem", "ntru", "frodo", "sntrup"]):
                            has_pq = True
                            break

                    if has_pq:
                        # Has PQ groups - need to check if also has classical
                        has_classical = any(c in g.lower() for g in entry.get("supported_groups", [])
                                          for c in ["x25519", "x448", "secp", "ffdhe"])
                        entry["post_quantum_secure"] = "Hybrid" if has_classical else "Yes"
                    else:
                        # Has groups but no PQ = classical only
                        entry["post_quantum_secure"] = "No"
                else:
                    # No groups = decryption failed or no PQ, assume classical
                    entry["post_quantum_secure"] = "No"

                fixed_count += 1

    return fixed_count

def main():
    input_file = Path(sys.argv[1] if len(sys.argv) > 1 else "stinky.json")

    if not input_file.exists():
        print(f"ERROR: {input_file} not found", file=sys.stderr)
        sys.exit(1)

    print(f"Loading {input_file}...")
    with open(input_file) as f:
        data = json.load(f)

    print(f"Loaded {len(data)} entries")

    # Count before
    unknown_before = sum(1 for entry in data if entry.get("post_quantum_secure") == "Unknown")
    print(f"  Unknown: {unknown_before}")

    # Fix
    fixed_count = fix_pq_status(data)
    print(f"Fixed {fixed_count} entries")

    # Count after
    status_counts = {}
    for entry in data:
        status = entry.get("post_quantum_secure", "Unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    print("\nFinal distribution:")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count}")

    # Save
    backup_file = input_file.with_suffix(".json.backup")
    print(f"\nBacking up to {backup_file}")
    input_file.rename(backup_file)

    print(f"Writing fixed data to {input_file}")
    with open(input_file, "w") as f:
        json.dump(data, f, indent=2)

    print("Done!")

if __name__ == "__main__":
    main()
