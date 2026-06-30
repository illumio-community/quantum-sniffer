# Ansible Playbook for Quantum-Sniffer

Run quantum-sniffer on remote hosts without permanent installation. Creates temporary environment, runs scan, fetches results, and cleans up completely.

## Overview

The playbook:
1. Creates temporary directory on remote host
2. Copies quantum-sniffer source code
3. Creates Python virtual environment
4. Installs dependencies (scapy, cryptography)
5. Runs quantum-sniffer scan
6. Fetches results to control machine
7. Deletes temporary directory (cleanup guaranteed)

**Result:** Zero permanent changes to remote system.

## Prerequisites

### On Control Machine (where you run ansible)

```bash
# Install Ansible
sudo apt install ansible

# Or via pip
pip install ansible

# Verify
ansible --version
```

### On Remote Hosts (target machines)

**Required:**
- Python 3.9+ (usually pre-installed)
- SSH access with key-based authentication

**Optional:**
- sudo access (only needed for passive capture mode)
- Internet access (for pip to download dependencies)

**No installation needed** - playbook handles everything temporarily.

## Quick Start

### 1. Configure Inventory

Edit `inventory.ini` and add your hosts:

```ini
[production]
web-prod-1 ansible_host=10.1.1.50 ansible_user=upce
web-prod-2 ansible_host=10.1.1.51 ansible_user=upce
db-prod-1 ansible_host=10.1.1.100 ansible_user=upce

[staging]
web-staging-1 ansible_host=10.1.2.50 ansible_user=upce
```

### 2. Test Connectivity

```bash
ansible -i inventory.ini scan_targets -m ping
```

### 3. Run Scan

```bash
# Scan all hosts (they scan themselves)
ansible-playbook -i inventory.ini run-quantum-sniffer.yml

# Scan specific group
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -l production

# Scan single host
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -l web-prod-1
```

### 4. View Results

Results are saved in `ansible/results/`:

```bash
ls ansible/results/
# web-prod-1-2026-06-29-scan.json
# web-prod-1-2026-06-29-scan.md
# db-prod-1-2026-06-29-scan.json
# db-prod-1-2026-06-29-scan.md

# View markdown report
less ansible/results/web-prod-1-2026-06-29-scan.md

# Query JSON with jq
jq '.summary' ansible/results/web-prod-1-2026-06-29-scan.json
```

## Usage Examples

### Scan Each Host's Own Services

Default behavior - each host scans itself:

```bash
ansible-playbook -i inventory.ini run-quantum-sniffer.yml
```

Each host probes its own IP address on ports 22, 443, 3389.

### Scan a Different Target

Override `scan_target` to scan something else:

```bash
# Scan a specific IP from each host
ansible-playbook -i inventory.ini run-quantum-sniffer.yml \
  -e "scan_target=10.1.1.100"

# Scan a subnet from each host
ansible-playbook -i inventory.ini run-quantum-sniffer.yml \
  -e "scan_target=10.1.1.0/24"

# Scan multiple IPs
ansible-playbook -i inventory.ini run-quantum-sniffer.yml \
  -e "scan_target=10.1.1.50,10.1.1.51,10.1.1.52"
```

### Custom Port List

```bash
ansible-playbook -i inventory.ini run-quantum-sniffer.yml \
  -e "scan_ports=22,25,80,110,143,443,587,993,995"
```

### Adjust Timeout and Workers

```bash
ansible-playbook -i inventory.ini run-quantum-sniffer.yml \
  -e "scan_timeout=3 scan_workers=20"
```

### Passive Capture Mode

Requires sudo on remote hosts:

```bash
ansible-playbook -i inventory.ini run-quantum-sniffer.yml \
  -e "scan_mode=passive" \
  --become \
  --ask-become-pass
```

This runs passive packet capture for 10 minutes, then fetches CSV/JSONL results.

### Scan Specific Hosts

```bash
# By group
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -l production

# By hostname
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -l web-prod-1

# By pattern
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -l "web-*"

# Multiple hosts
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -l "web-prod-1,db-prod-1"
```

### Parallel Execution

Control parallelism with `-f`:

```bash
# Run on 10 hosts simultaneously
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -f 10

# Serial execution (one at a time)
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -f 1
```

### Dry Run (Check Mode)

Test what would happen without actually running:

```bash
ansible-playbook -i inventory.ini run-quantum-sniffer.yml --check
```

Note: Check mode will still create temp directories but won't run the actual scan.

## Integration with UPCE

### Use UPCE Inventory

Import hosts from UPCE inventory:

```python
#!/usr/bin/env python3
# generate-ansible-inventory.py
import json
import sys

# Read UPCE inventory
with open('../common/inventory.json') as f:
    upce_inventory = json.load(f)

# Generate Ansible inventory
print("[scan_targets]")
for workload in upce_inventory.get('workloads', []):
    name = workload['name']
    ips = workload.get('ips', [])
    if ips and workload.get('credentials', {}).get('username') != 'placeholder':
        ip = ips[0]
        user = workload['credentials']['username']
        print(f"{name} ansible_host={ip} ansible_user={user}")
```

Run:
```bash
python3 generate-ansible-inventory.py > ansible/inventory-from-upce.ini
ansible-playbook -i ansible/inventory-from-upce.ini run-quantum-sniffer.yml
```

### Scan and Label in Illumio

After scanning, label workloads in Illumio PCE:

```bash
# 1. Scan all hosts
ansible-playbook -i inventory.ini run-quantum-sniffer.yml

# 2. Label in Illumio (from control machine)
for json_file in ansible/results/*.json; do
  ip=$(jq -r '.results[0].target_ip' "$json_file")
  if [ "$ip" != "null" ]; then
    quantum-sniffer --probe "$ip" --ports 22,443 --illumio-label "$ip"
  fi
done

# 3. View summary
quantum-sniffer --illumio-summary
```

## Variables Reference

Override any variable with `-e`:

### Scan Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `scan_mode` | `probe` | Mode: `probe` or `passive` |
| `scan_target` | `{{ ansible_default_ipv4.address }}` | Target to scan (IP, CIDR, range) |
| `scan_ports` | `22,443,3389` | Comma-separated port list |
| `scan_timeout` | `5` | Connection timeout (seconds) |
| `scan_workers` | `10` | Parallel workers for bulk scans |

### Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `temp_dir` | `/tmp/quantum-sniffer-<epoch>-<hostname>` | Temporary directory on remote |
| `quantum_sniffer_source` | `{{ playbook_dir }}/..` | Local quantum-sniffer source |
| `results_dir` | `{{ playbook_dir }}/results` | Results directory on control machine |

### Output Files

| Variable | Default | Description |
|----------|---------|-------------|
| `output_json` | `<temp_dir>/scan-results.json` | JSON output path |
| `output_markdown` | `<temp_dir>/scan-results.md` | Markdown output path |
| `output_csv` | `<temp_dir>/scan-results.csv` | CSV output (passive mode) |
| `output_jsonl` | `<temp_dir>/scan-results.jsonl` | JSONL output (passive mode) |

## Advanced Usage

### Custom Inventory Variables

Set per-host variables in inventory:

```ini
[production]
web-prod-1 ansible_host=10.1.1.50 scan_ports=80,443,8443
db-prod-1 ansible_host=10.1.1.100 scan_ports=3306,5432
```

### Vault for Credentials

Store sensitive data in Ansible Vault:

```bash
# Create vault
ansible-vault create vault.yml

# Add to vault.yml:
ansible_become_password: your-sudo-password

# Use vault
ansible-playbook -i inventory.ini run-quantum-sniffer.yml \
  --ask-vault-pass
```

### Tags (Future Enhancement)

Add tags to playbook for selective execution:

```yaml
# In playbook
- name: Install dependencies
  tags: setup
  ...

- name: Run scan
  tags: scan
  ...
```

Run only setup or scan:
```bash
ansible-playbook -i inventory.ini run-quantum-sniffer.yml --tags setup
ansible-playbook -i inventory.ini run-quantum-sniffer.yml --tags scan
```

### Logging

Enable verbose output:

```bash
# Standard verbose
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -v

# More verbose (show task details)
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -vv

# Debug level (show everything)
ansible-playbook -i inventory.ini run-quantum-sniffer.yml -vvv
```

## Troubleshooting

### Python Not Found

**Error:** `Python 3 is required but not found`

**Solution:** Install Python 3 on remote host:
```bash
sudo apt install python3
```

### SSH Connection Failed

**Error:** `Failed to connect to the host via ssh`

**Solution:** Check SSH keys:
```bash
# Test SSH
ssh user@remote-host

# Copy SSH key if needed
ssh-copy-id user@remote-host
```

### Permission Denied (Passive Mode)

**Error:** `ERROR: Live capture requires root`

**Solution:** Run with `--become`:
```bash
ansible-playbook -i inventory.ini run-quantum-sniffer.yml \
  -e "scan_mode=passive" \
  --become --ask-become-pass
```

### Pip Install Fails (No Internet)

**Error:** `Could not find a version that satisfies the requirement`

**Solution 1:** Pre-download dependencies:
```bash
# On a machine with internet
pip download -d /tmp/quantum-deps scapy cryptography python-dotenv

# Copy to remote hosts
ansible -i inventory.ini scan_targets -m copy \
  -a "src=/tmp/quantum-deps dest=/tmp/"

# Install from local files
pip install --no-index --find-links /tmp/quantum-deps scapy
```

**Solution 2:** Use standalone binary instead (see Option 2 in main docs)

### Cleanup Failed

**Error:** `Temporary directory STILL EXISTS`

**Solution:** Manual cleanup:
```bash
ansible -i inventory.ini scan_targets -m shell \
  -a "rm -rf /tmp/quantum-sniffer-*"
```

### Slow Performance

**Cause:** pip install on every run

**Solutions:**
1. Use faster workers: `-e "scan_workers=20"`
2. Reduce timeout: `-e "scan_timeout=3"`
3. Use standalone binary (Option 2)
4. Cache dependencies (future enhancement)

## Performance Considerations

### Execution Time

Typical timing for one host:
- Temp setup: 5 seconds
- Pip install: 30-60 seconds (first time, depends on internet)
- Scan (10 hosts × 3 ports): 10-30 seconds
- Cleanup: 2 seconds
- **Total:** ~1-2 minutes per host

### Optimization Tips

1. **Parallel execution:** `-f 10` (10 hosts at once)
2. **Reduce timeout:** `-e "scan_timeout=3"`
3. **Target specific ports:** `-e "scan_ports=22,443"`
4. **Batch by network:** Scan different subnets from different hosts

### Scaling

For 100+ hosts:
- Use dynamic inventory (from UPCE, CMDB, etc.)
- Run in batches: `-l "batch1"`, `-l "batch2"`
- Consider distributed execution (Ansible Tower/AWX)

## Security Considerations

### SSH Keys

- Use key-based authentication (no passwords in inventory)
- Limit key access with `from=` in `authorized_keys`
- Use separate keys for scanning vs. admin

### Sudo Access

- Passive mode needs root (for packet capture)
- Use `NOPASSWD` in sudoers for automation:
  ```
  upce ALL=(ALL) NOPASSWD: /usr/bin/python3
  ```

### Cleanup Guarantee

- Playbook uses `always:` block for cleanup
- Even if scan fails, temp directory is removed
- Verify with `--check` mode first

### Results Storage

- Results saved to `ansible/results/` on control machine
- Secure this directory (contains network topology)
- Consider encryption at rest

## Maintenance

### Update Dependencies

Edit playbook to update package versions:

```yaml
- name: Create requirements.txt if missing
  copy:
    content: |
      scapy>=2.5.0
      cryptography>=42.0.0  # Update version here
```

### Add Custom Arguments

Extend playbook with more quantum-sniffer flags:

```yaml
- name: Run quantum-sniffer (probe mode)
  command: >
    {{ temp_dir }}/venv/bin/python3 -m quantum_sniffer
    --probe {{ scan_target }}
    --ports {{ scan_ports }}
    --output-json {{ output_json }}
    --output-markdown {{ output_markdown }}
    --sni {{ scan_sni | default('') }}  # Add custom flag
```

## Examples

See `examples/` directory for:
- `scan-production.sh` - Scan all production hosts
- `scan-and-label.sh` - Scan + Illumio labeling workflow
- `bulk-compliance-check.sh` - Generate compliance reports

## Support

- **Ansible Docs:** https://docs.ansible.com/
- **Quantum-Sniffer:** See main README.md
- **Issues:** Report problems with the playbook in GitHub

## License

GNU General Public License v3.0 (same as quantum-sniffer)
