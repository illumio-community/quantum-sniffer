# Deep Bug Analysis - sniffy.py

## Critical Bugs (Buffer Overflow / Memory Safety)

### 1. **Line 642: Session ID length not validated before use**
```python
sid_len = body[pos]; pos += 1 + sid_len
```
**Problem**: Reads `sid_len` from `body[pos]` and immediately advances `pos` by `1 + sid_len` without checking if `pos + 1 + sid_len <= len(body)`. If a malicious packet claims sid_len=255, this could read way past the buffer end on subsequent operations.

**Impact**: Could cause out-of-bounds reads on subsequent parsing, or cause the parser to miss actual data.

**Fix**: Add bounds check:
```python
if pos >= len(body): return result
sid_len = body[pos]
if pos + 1 + sid_len > len(body): return result
pos += 1 + sid_len
```

### 2. **Line 654: Compression length not validated**
```python
if pos < len(body): comp_len = body[pos]; pos += 1 + comp_len
```
**Problem**: Same as #1 - reads compression length and advances position without validating the length is within bounds.

**Impact**: Could advance `pos` beyond buffer length, causing subsequent checks to pass incorrectly or miss data.

**Fix**: Add bounds check:
```python
if pos < len(body):
    comp_len = body[pos]
    if pos + 1 + comp_len > len(body): return result
    pos += 1 + comp_len
```

### 3. **Line 661: Another session ID validation bug**
```python
sid_len = body[pos]; pos += 1 + sid_len
```
**Problem**: Same pattern as #1, in ServerHello parsing.

**Fix**: Same as #1.

### 4. **Line 1350: QUIC TLS parsing - missing validation**
```python
cs_len = struct.unpack(">H", body[pos:pos+2])[0]
pos += 2 + cs_len + 1  # ciphers + compression_len
```
**Problem**: Advances position by `cs_len + 1` without checking if:
  - The cipher suite data (cs_len bytes) is actually available
  - The compression_len byte exists

**Impact**: In QUIC Initial packet decryption, could cause misparse of TLS ClientHello.

**Fix**:
```python
cs_len = struct.unpack(">H", body[pos:pos+2])[0]
if pos + 2 + cs_len + 1 > len(body): 
    break  # or return/continue as appropriate
pos += 2 + cs_len + 1
```

### 5. **Line 1360: Extension data length not validated**
```python
ext_data = body[pos+4:pos+4+ext_data_len]
```
**Problem**: Creates `ext_data` slice without checking if `pos + 4 + ext_data_len <= len(body)`. While Python slicing won't crash, this creates a truncated slice that could lead to parsing errors.

**Impact**: Extension data could be truncated, leading to incomplete parsing or missed PQ indicators.

**Fix**:
```python
if pos + 4 + ext_data_len > len(body):
    break  # Extension claims more data than available
ext_data = body[pos+4:pos+4+ext_data_len]
```

## Medium Severity Bugs

### 6. **Line 949: Bare except clause**
```python
except:
    pass
```
**Problem**: Catches ALL exceptions including `KeyboardInterrupt` and `SystemExit`, which should not be caught.

**Impact**: Could make it difficult to interrupt the program with Ctrl+C in this code path.

**Fix**:
```python
except Exception:
    pass
```

### 7. **Line 1371: No validation before position increment**
```python
pos += 4 + ext_data_len
```
**Problem**: While the loop checks `pos + 4 <= ext_end and pos + 4 <= len(body)`, after reading ext_data_len, there's no guarantee that incrementing by `4 + ext_data_len` won't exceed bounds.

**Impact**: Could cause loop to continue with invalid position, potentially reading garbage data.

**Fix**: Add check after reading ext_data_len:
```python
if pos + 4 + ext_data_len > len(body):
    break
pos += 4 + ext_data_len
```

## Logic Bugs

### 8. **Line 1350: Assumption about compression**
```python
pos += 2 + cs_len + 1  # ciphers + compression_len
```
**Problem**: Assumes compression methods length is always 1 byte. In TLS 1.3 within QUIC, compression is deprecated and this field should be 1 byte containing 0x00. But the code doesn't read the compression_len value - it just assumes "+1".

**Impact**: If the field is malformed or this is not actually TLS 1.3, the parser could get out of sync.

**Fix**: Actually read the compression length:
```python
pos += 2 + cs_len
if pos >= len(body): break
comp_len = body[pos]
if pos + 1 + comp_len > len(body): break
pos += 1 + comp_len
```

### 9. **Lines 642, 654, 661, 1346: Reading bytes from potentially short buffers**
All instances of `xxx_len = body[pos]` should check `pos < len(body)` first.

## Test Cases That Would Trigger These Bugs

1. **Malformed TLS ClientHello with large session ID**: Create packet with sid_len=255 but only 10 bytes following
2. **Truncated TLS ServerHello**: Packet ends right after cipher suite selection
3. **Malicious QUIC Initial packet**: Crafted to have truncated TLS ClientHello in CRYPTO frame
4. **Extension with claimed length exceeding packet**: ext_data_len = 0xFFFF in a 200-byte packet

## Recommended Action

All buffer parsing in `_parse_tls_hello_raw()` and the QUIC TLS extraction code (lines 1340-1376) needs systematic bounds checking before:
1. Reading any length field from a buffer
2. Incrementing position by any length field value
3. Creating slices using length field values
