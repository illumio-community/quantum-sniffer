#!/usr/bin/env python3
"""
Self-scan for post-quantum crypto support.

Discovers externally-accessible services on this machine and tests them
with quantum-sniffer. Outputs results in JSON format.

Designed to run daily via cron:
  0 2 * * * /path/to/self-scan.py > /var/log/quantum-self-scan.json

Features:
- Discovers services listening on 0.0.0.0 or specific external IPs
- Excludes localhost-only services (127.0.0.1, ::1)
- Runs active probes (not passive capture)
- Outputs complete JSON results
- Suitable for daily automated execution
"""

import json
import sys
import subprocess
import os
from pathlib import Path
from datetime import datetime
import socket


def discover_external_services():
    """Run discovery script to find external services."""
    script_dir = Path(__file__).parent
    discover_script = script_dir / 'discover-external-services.py'

    if not discover_script.exists():
        return {
            'error': 'discover-external-services.py not found',
            'primary_ip': None,
            'ports': []
        }

    try:
        result = subprocess.run(
            [str(discover_script)],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0 and not result.stdout:
            return {
                'error': f'Discovery failed: {result.stderr}',
                'primary_ip': None,
                'ports': []
            }

        return json.loads(result.stdout)

    except subprocess.TimeoutExpired:
        return {
            'error': 'Discovery timed out',
            'primary_ip': None,
            'ports': []
        }
    except json.JSONDecodeError as e:
        return {
            'error': f'Failed to parse discovery output: {e}',
            'primary_ip': None,
            'ports': []
        }
    except Exception as e:
        return {
            'error': f'Discovery failed: {e}',
            'primary_ip': None,
            'ports': []
        }


def run_quantum_sniffer(target_ip, ports, timeout=5):
    """
    Run quantum-sniffer probe against target IP and ports.

    Returns parsed JSON results or error dict.
    """
    # Find quantum-sniffer in venv or system
    quantum_sniffer_cmd = None

    # Try venv first
    script_dir = Path(__file__).parent
    venv_python = script_dir / 'venv' / 'bin' / 'python3'
    if venv_python.exists():
        quantum_sniffer_cmd = [str(venv_python), '-m', 'quantum_sniffer']
    else:
        # Try system installation
        try:
            subprocess.run(['quantum-sniffer', '--help'],
                          capture_output=True, timeout=2)
            quantum_sniffer_cmd = ['quantum-sniffer']
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Try python module
            try:
                subprocess.run(['python3', '-m', 'quantum_sniffer', '--help'],
                              capture_output=True, timeout=2)
                quantum_sniffer_cmd = ['python3', '-m', 'quantum_sniffer']
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return {
                    'error': 'quantum-sniffer not found (try: pip install quantum-sniffer)',
                    'results': []
                }

    # Build command
    ports_str = ','.join(map(str, ports))

    # Use temp file for JSON output to avoid truncation issues
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
        tmp_path = tmp_file.name

    try:
        cmd = quantum_sniffer_cmd + [
            '--probe', target_ip,
            '--ports', ports_str,
            '--timeout', str(timeout),
            '--workers', '10',
            '--output-json', tmp_path
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=len(ports) * timeout + 30  # Extra buffer
        )

        # Read JSON from temp file
        try:
            with open(tmp_path, 'r') as f:
                json_output = json.load(f)
            return json_output
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return {
                'error': f'Failed to parse quantum-sniffer output: {e}',
                'stdout': result.stdout[:500],  # First 500 chars
                'stderr': result.stderr[:500],
                'results': []
            }
        finally:
            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    except subprocess.TimeoutExpired:
        return {
            'error': 'quantum-sniffer timed out',
            'results': []
        }
    except Exception as e:
        return {
            'error': f'Failed to run quantum-sniffer: {e}',
            'results': []
        }


def get_hostname():
    """Get system hostname."""
    try:
        return socket.gethostname()
    except Exception:
        return 'unknown'


def main():
    """Main entry point."""
    start_time = datetime.now()
    start_time_iso = start_time.isoformat()

    # Build result structure
    output = {
        'scan_info': {
            'hostname': get_hostname(),
            'timestamp': start_time_iso,
            'scan_type': 'self-scan',
            'tool': 'quantum-sniffer self-scan',
            'version': '0.4.1'
        },
        'discovery': {},
        'scan_results': {},
        'summary': {},
        'errors': []
    }

    # Step 1: Discover external services
    print("Discovering externally-accessible services...", file=sys.stderr)
    discovery = discover_external_services()
    output['discovery'] = discovery

    if 'error' in discovery:
        output['errors'].append(f"Discovery error: {discovery['error']}")

    primary_ip = discovery.get('primary_ip')
    ports = discovery.get('ports', [])

    if not primary_ip:
        output['errors'].append('Could not determine primary IP address')
        print(json.dumps(output, indent=2))
        return 1

    if not ports:
        output['errors'].append('No externally-accessible ports found')
        print(json.dumps(output, indent=2))
        return 1

    print(f"Found {len(ports)} external port(s) on {primary_ip}", file=sys.stderr)
    print(f"Ports: {', '.join(map(str, ports))}", file=sys.stderr)

    # Step 2: Run quantum-sniffer scan
    print(f"Scanning {primary_ip}...", file=sys.stderr)
    scan_results = run_quantum_sniffer(primary_ip, ports)
    output['scan_results'] = scan_results

    if 'error' in scan_results:
        output['errors'].append(f"Scan error: {scan_results['error']}")

    # Step 3: Generate summary
    results_list = scan_results.get('results', [])

    total_ports = len(results_list)
    open_ports = sum(1 for r in results_list if r.get('status') == 'open')
    pq_capable = sum(1 for r in results_list
                     if r.get('status') == 'open' and
                     r.get('post_quantum_secure') in ['Yes', 'Hybrid'])

    output['summary'] = {
        'total_ports_scanned': total_ports,
        'open_ports': open_ports,
        'closed_ports': sum(1 for r in results_list if r.get('status') == 'closed'),
        'pq_capable_ports': pq_capable,
        'pq_percentage': (pq_capable / open_ports * 100) if open_ports > 0 else 0
    }

    # Add timing
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    output['scan_info']['end_time'] = end_time.isoformat()
    output['scan_info']['duration_seconds'] = round(duration, 2)

    # Output JSON
    print(json.dumps(output, indent=2))

    # Print summary to stderr for human readability
    print("", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("Self-Scan Complete", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"Hostname: {output['scan_info']['hostname']}", file=sys.stderr)
    print(f"Primary IP: {primary_ip}", file=sys.stderr)
    print(f"Open Ports: {open_ports}/{total_ports}", file=sys.stderr)
    print(f"PQ-Capable: {pq_capable}/{open_ports} ({output['summary']['pq_percentage']:.1f}%)", file=sys.stderr)
    print(f"Duration: {duration:.1f}s", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
