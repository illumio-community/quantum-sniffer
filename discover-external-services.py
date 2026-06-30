#!/usr/bin/env python3
"""
Discover externally-accessible network services on this machine.

Finds services listening on:
- 0.0.0.0 (all interfaces)
- Specific non-localhost IP addresses

Excludes services only listening on:
- 127.0.0.1 (localhost IPv4)
- ::1 (localhost IPv6)

Returns JSON with discovered ports and primary external IP.
"""

import json
import subprocess
import sys
import re
from collections import defaultdict


def get_primary_ip():
    """Get primary non-localhost IP address."""
    try:
        # Try to get default route interface IP
        result = subprocess.run(
            ['ip', 'route', 'get', '1.1.1.1'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Parse output: "1.1.1.1 via ... dev eth0 src 10.1.1.50 ..."
            match = re.search(r'src\s+(\S+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass

    # Fallback: try hostname -I
    try:
        result = subprocess.run(
            ['hostname', '-I'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            ips = result.stdout.strip().split()
            # Return first non-localhost IP
            for ip in ips:
                if not ip.startswith('127.') and not ip.startswith('::'):
                    return ip
    except Exception:
        pass

    return None


def parse_ss_output():
    """Parse 'ss -tuln' output to find listening ports."""
    try:
        result = subprocess.run(
            ['ss', '-tuln'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error running ss: {e}", file=sys.stderr)
        return None


def parse_netstat_output():
    """Parse 'netstat -tuln' output to find listening ports."""
    try:
        result = subprocess.run(
            ['netstat', '-tuln'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error running netstat: {e}", file=sys.stderr)
        return None


def parse_listening_ports(output, tool='ss'):
    """
    Parse ss or netstat output to extract listening ports.

    Returns dict: {port: [list of bind addresses]}
    """
    ports = defaultdict(set)

    lines = output.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('Netid') or line.startswith('Proto'):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        # Check if LISTEN state
        if tool == 'netstat':
            if 'LISTEN' not in line:
                continue
            # netstat format: Proto Recv-Q Send-Q Local-Address Foreign-Address State
            local_addr = parts[3]
        else:  # ss
            state = parts[1] if len(parts) > 1 else ''
            if 'LISTEN' not in state:
                continue
            # ss format: Netid State Recv-Q Send-Q Local-Address:Port Peer-Address:Port
            local_addr = parts[4] if len(parts) > 4 else ''

        # Parse address:port or [ipv6]:port
        if ':' not in local_addr:
            continue

        # Handle IPv6 [addr]:port format
        if local_addr.startswith('['):
            match = re.match(r'\[([^\]]+)\]:(\d+)', local_addr)
            if match:
                addr, port = match.groups()
            else:
                continue
        else:
            # IPv4 addr:port format
            addr, port = local_addr.rsplit(':', 1)

        try:
            port = int(port)
        except ValueError:
            continue

        ports[port].add(addr)

    return ports


def filter_external_ports(ports):
    """
    Filter ports to only include those accessible externally.

    Returns list of ports that are listening on 0.0.0.0, ::, or specific non-localhost IPs.
    """
    external_ports = set()

    localhost_addrs = {'127.0.0.1', '::1', 'localhost'}
    wildcard_addrs = {'0.0.0.0', '::', '*'}

    for port, addresses in ports.items():
        # Check if listening on wildcard (0.0.0.0 or ::)
        if any(addr in wildcard_addrs for addr in addresses):
            external_ports.add(port)
            continue

        # Check if listening on any non-localhost address
        non_localhost = addresses - localhost_addrs
        if non_localhost:
            external_ports.add(port)

    return sorted(external_ports)


def discover_external_services():
    """
    Discover externally-accessible services on this machine.

    Returns dict with:
    - primary_ip: Primary non-localhost IP address
    - ports: List of externally-accessible ports
    - details: Dict of port -> bind addresses
    """
    # Get primary IP
    primary_ip = get_primary_ip()

    # Try ss first, fall back to netstat
    output = parse_ss_output()
    tool = 'ss'

    if output is None:
        output = parse_netstat_output()
        tool = 'netstat'

    if output is None:
        return {
            'error': 'Neither ss nor netstat available',
            'primary_ip': primary_ip,
            'ports': [],
            'details': {}
        }

    # Parse listening ports
    all_ports = parse_listening_ports(output, tool)

    # Filter to external only
    external_ports = filter_external_ports(all_ports)

    # Build details dict (for debugging)
    details = {}
    for port in external_ports:
        details[port] = list(all_ports[port])

    return {
        'primary_ip': primary_ip,
        'ports': external_ports,
        'details': details,
        'tool_used': tool
    }


def main():
    """Main entry point."""
    result = discover_external_services()

    # Output JSON
    print(json.dumps(result, indent=2))

    # Exit with error if no ports found
    if not result.get('ports'):
        print("Warning: No externally-accessible ports found", file=sys.stderr)
        sys.exit(1)

    return 0


if __name__ == '__main__':
    sys.exit(main())
