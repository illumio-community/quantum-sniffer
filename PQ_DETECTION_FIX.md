# Post-Quantum Detection Fix

## Problem
When visiting `https://pq.cloudflareresearch.com/`, sniffy incorrectly reported "quantum-unsafe" (CLASSICAL CRYPTO) instead of detecting the X25519Kyber768 hybrid key exchange.

## Root Cause
**Missing group ID 0x11ec** in the TLS_NAMED_GROUPS dictionary.

Cloudflare and Google use the official IANA-assigned group ID **0x11ec** for X25519Kyber768, but sniffy only had Chrome's experimental ID (0x6399). When sniffy encountered 0x11ec, it failed to recognize it as a post-quantum group.

## Solution
Added the missing group ID to `TLS_NAMED_GROUPS`:

```python
TLS_NAMED_GROUPS = {
    # ... existing groups ...
    0x11eb: "x25519kyber512",
    0x11ec: "x25519kyber768",   # IANA-assigned (Cloudflare, Google) ← ADDED
    0x6399: "x25519kyber768",   # Chrome/BoringSSL experimental
    0x639a: "x25519mlkem768",   # Chrome/BoringSSL ML-KEM draft
}
```

Updated validation ranges in the key_share parser:
```python
0x11eb <= candidate <= 0x11ec or  # x25519kyber512, x25519kyber768
```

## Verification
Tested with multiple sites using 0x11ec:
- ✅ `pq.cloudflareresearch.com`
- ✅ `update.googleapis.com`
- ✅ `static.cloudflareinsights.com`

**Before fix:**
```
Post-Quantum: CLASSICAL CRYPTO (quantum-vulnerable)
Key Exchange Groups: (parsing failed or not recognized)
```

**After fix:**
```
Post-Quantum: HYBRID (PQ + Classical)
Key Exchange Groups:
  - x25519kyber768 [POST-QUANTUM]
```

## Technical Details

### X25519Kyber768 Hybrid KEX
- **Group ID**: 0x11ec (4588 decimal) - IANA-assigned
- **Key exchange size**: ~1120 bytes (32 bytes X25519 + 1088 bytes Kyber768)
- **Components**:
  - X25519: Classical elliptic curve (ECDHE)
  - Kyber768: Post-quantum KEM (lattice-based, NIST Level 3)
- **Classification**: Hybrid (protects against both classical and quantum computers)

### Why Hybrid?
The connection is classified as "Hybrid" because:
1. "kyber" matches PQ_SAFE_KEX → `pq_kex = True`
2. "x25519" matches CLASSICAL_KEX → `classical_kex = True`
3. Both true → returns "Hybrid"

This is correct: X25519Kyber768 provides both classical ECDHE security AND post-quantum KEM security.

## Files Modified
- `sniffy.py` (lines 140-151, 967-973)

## Backward Compatibility
Fully backward compatible. Existing group IDs continue to work. New group ID 0x11ec now recognized.
