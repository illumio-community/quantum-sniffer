#!/usr/bin/env python3
"""
Generate Ansible inventory from UPCE inventory.json

Usage:
  ./generate-inventory-from-upce.py > inventory-from-upce.ini
  ansible-playbook -i inventory-from-upce.ini run-quantum-sniffer.yml
"""

import json
import sys
import os
from pathlib import Path


def load_upce_inventory(inventory_path):
    """Load UPCE inventory.json file."""
    try:
        with open(inventory_path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: File not found: {inventory_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {inventory_path}: {e}", file=sys.stderr)
        sys.exit(1)


def get_workload_labels(workload):
    """Extract labels from workload as dict."""
    labels = {}
    for label in workload.get('labels', []):
        key = label.get('key', '')
        value = label.get('value', '')
        if key and value:
            labels[key] = value
    return labels


def workload_to_ansible_host(workload):
    """Convert UPCE workload to Ansible host entry."""
    name = workload.get('name', 'unknown')
    ips = workload.get('ips', [])

    # Skip if no IPs
    if not ips:
        return None

    # Get primary IP
    primary_ip = ips[0]

    # Get credentials
    credentials = workload.get('credentials', {})
    username = credentials.get('username', '')

    # Skip if placeholder credentials
    if username == 'placeholder' or not username:
        return None

    # Get mode (skip if mode is 'none' or False)
    mode = workload.get('mode', 'enforced')
    if mode in ['none', False, 'remove']:
        return None

    # Build host entry
    host_entry = f"{name} ansible_host={primary_ip} ansible_user={username}"

    # Add labels as host variables (for filtering)
    labels = get_workload_labels(workload)
    if labels:
        for key, value in labels.items():
            # Sanitize for Ansible variable names
            var_name = f"upce_label_{key.replace('-', '_')}"
            host_entry += f" {var_name}={value}"

    # Add UPCE metadata
    os_type = workload.get('os', 'unknown')
    fwtype = workload.get('fwtype', 'unknown')
    host_entry += f" upce_os={os_type} upce_fwtype={fwtype} upce_mode={mode}"

    return host_entry


def generate_inventory(upce_inventory):
    """Generate Ansible inventory from UPCE inventory."""
    workloads = upce_inventory.get('workloads', [])

    # Group by labels
    groups = {}

    for workload in workloads:
        host_entry = workload_to_ansible_host(workload)
        if not host_entry:
            continue

        # Get labels for grouping
        labels = get_workload_labels(workload)

        # Add to label-based groups
        for key, value in labels.items():
            group_name = f"label_{key}_{value}".replace('-', '_').replace('.', '_')
            if group_name not in groups:
                groups[group_name] = []
            groups[group_name].append(host_entry)

        # Add to OS group
        os_type = workload.get('os', 'unknown')
        os_group = f"os_{os_type}".replace('-', '_')
        if os_group not in groups:
            groups[os_group] = []
        groups[os_group].append(host_entry)

        # Add to mode group
        mode = workload.get('mode', 'enforced')
        mode_group = f"mode_{mode}".replace('-', '_')
        if mode_group not in groups:
            groups[mode_group] = []
        groups[mode_group].append(host_entry)

        # Add to 'all' group
        if 'all_workloads' not in groups:
            groups['all_workloads'] = []
        groups['all_workloads'].append(host_entry)

    return groups


def print_inventory(groups):
    """Print Ansible inventory in INI format."""
    print("# Ansible inventory generated from UPCE inventory.json")
    print(f"# Generated: {os.popen('date').read().strip()}")
    print("#")
    print("# Usage:")
    print("#   ansible-playbook -i inventory-from-upce.ini run-quantum-sniffer.yml")
    print("#   ansible-playbook -i inventory-from-upce.ini run-quantum-sniffer.yml -l label_env_prod")
    print()

    # Print [scan_targets:children] with all groups
    print("[scan_targets:children]")
    for group_name in sorted(groups.keys()):
        print(group_name)
    print()

    # Print each group
    for group_name in sorted(groups.keys()):
        print(f"[{group_name}]")
        # Deduplicate hosts (same host might be in multiple groups)
        unique_hosts = list(dict.fromkeys(groups[group_name]))
        for host_entry in unique_hosts:
            print(host_entry)
        print()

    # Print common variables
    print("[scan_targets:vars]")
    print("ansible_python_interpreter=/usr/bin/python3")
    print("# ansible_become=yes  # Uncomment if sudo needed")
    print()


def main():
    """Main entry point."""
    # Find UPCE inventory
    script_dir = Path(__file__).parent
    upce_inventory_path = script_dir.parent.parent / 'common' / 'inventory.json'

    # Allow override via argument
    if len(sys.argv) > 1:
        upce_inventory_path = Path(sys.argv[1])

    if not upce_inventory_path.exists():
        print(f"ERROR: UPCE inventory not found: {upce_inventory_path}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Usage:", file=sys.stderr)
        print(f"  {sys.argv[0]} [path/to/inventory.json]", file=sys.stderr)
        sys.exit(1)

    # Load and generate
    upce_inventory = load_upce_inventory(upce_inventory_path)
    groups = generate_inventory(upce_inventory)

    if not groups:
        print("WARNING: No valid workloads found in UPCE inventory", file=sys.stderr)
        sys.exit(1)

    # Print inventory
    print_inventory(groups)

    # Print summary to stderr
    total_hosts = len(set(host for hosts in groups.values() for host in hosts))
    print(f"# Generated {len(groups)} groups, {total_hosts} unique hosts", file=sys.stderr)


if __name__ == '__main__':
    main()
