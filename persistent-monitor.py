#!/usr/bin/env python3
"""
Persistent PQC monitoring daemon.

Continuously captures and analyzes network traffic for post-quantum crypto usage.
Designed to run as a long-lived daemon, logging PQC status of all connections.

Features:
- Passive monitoring (no active probing)
- Automatic interface detection
- Rolling log files with rotation
- Graceful shutdown handling
- Resource management

Usage:
  ./persistent-monitor.py                    # Monitor default interface
  ./persistent-monitor.py --interface eth0   # Monitor specific interface
  ./persistent-monitor.py --output-dir /var/log/quantum-sniffer  # Custom log directory
"""

import sys
import os
import json
import signal
import subprocess
import socket
import time
from pathlib import Path
from datetime import datetime
import argparse


def get_default_interface():
    """Get the default network interface."""
    try:
        # Get default route interface
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            # Parse "default via 10.22.0.1 dev ens3 ..."
            for line in result.stdout.split('\n'):
                if 'default' in line and 'dev' in line:
                    parts = line.split()
                    dev_idx = parts.index('dev')
                    if dev_idx + 1 < len(parts):
                        return parts[dev_idx + 1]

        # Fallback: try eth0, ens3, en0
        for iface in ['eth0', 'ens3', 'en0']:
            result = subprocess.run(
                ['ip', 'link', 'show', iface],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return iface

        return 'eth0'  # Final fallback
    except Exception as e:
        print(f"Warning: Could not detect interface: {e}", file=sys.stderr)
        return 'eth0'


def get_hostname():
    """Get system hostname."""
    try:
        return socket.gethostname()
    except:
        return 'unknown'


def find_quantum_sniffer():
    """Find quantum-sniffer executable."""
    # Try venv first
    script_dir = Path(__file__).parent
    venv_python = script_dir / 'venv' / 'bin' / 'python3'

    if venv_python.exists():
        return [str(venv_python), '-m', 'quantum_sniffer']

    # Try system
    try:
        subprocess.run(['quantum-sniffer', '--help'],
                      capture_output=True, timeout=2)
        return ['quantum-sniffer']
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try python module
    try:
        subprocess.run(['python3', '-m', 'quantum_sniffer', '--help'],
                      capture_output=True, timeout=2)
        return ['python3', '-m', 'quantum_sniffer']
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


def rotate_logs(output_dir, base_name, max_files=30):
    """Rotate log files, keeping only the most recent max_files."""
    try:
        log_files = []
        for ext in ['.jsonl', '.csv']:
            pattern = f"{base_name}*{ext}"
            log_files.extend(sorted(output_dir.glob(pattern)))

        if len(log_files) > max_files:
            for old_file in log_files[:-max_files]:
                old_file.unlink()
                print(f"Rotated old log: {old_file.name}")
    except Exception as e:
        print(f"Warning: Log rotation failed: {e}", file=sys.stderr)


class PersistentMonitor:
    """Daemon for continuous PQC monitoring."""

    def __init__(self, interface, output_dir, quiet=True):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.quiet = quiet
        self.process = None
        self.hostname = get_hostname()
        self.running = False

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Find quantum-sniffer
        self.cmd = find_quantum_sniffer()
        if not self.cmd:
            raise RuntimeError("quantum-sniffer not found (try: pip install quantum-sniffer)")

    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.stop()
        sys.exit(0)

    def start(self):
        """Start the monitoring daemon."""
        print(f"Starting persistent PQC monitoring on {self.hostname}")
        print(f"Interface: {self.interface}")
        print(f"Output directory: {self.output_dir}")
        print(f"Press Ctrl+C to stop\n")

        # Register signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.running = True

        while self.running:
            try:
                # Generate timestamped output filename
                timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
                output_base = self.output_dir / f"pqc-monitor-{self.hostname}-{timestamp}"

                # Build command
                cmd = self.cmd + [
                    '--interface', self.interface,
                    '--output', str(output_base),
                ]

                if self.quiet:
                    cmd.append('--quiet')

                print(f"[{datetime.now().isoformat()}] Starting capture session: {output_base.name}")

                # Run quantum-sniffer
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                # Monitor process
                while self.running:
                    retcode = self.process.poll()
                    if retcode is not None:
                        # Process exited
                        stdout, stderr = self.process.communicate()
                        if retcode != 0:
                            print(f"Warning: quantum-sniffer exited with code {retcode}")
                            if stderr:
                                print(f"Error: {stderr[:500]}")
                        break
                    time.sleep(1)

                # Rotate old logs
                rotate_logs(self.output_dir, 'pqc-monitor', max_files=30)

                if self.running:
                    # Restart after brief pause
                    print(f"[{datetime.now().isoformat()}] Session ended, restarting in 5 seconds...")
                    time.sleep(5)

            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                if self.running:
                    print("Restarting in 10 seconds...")
                    time.sleep(10)

    def stop(self):
        """Stop the monitoring daemon."""
        self.running = False
        if self.process and self.process.poll() is None:
            print("Stopping capture...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("Force killing process...")
                self.process.kill()
                self.process.wait()
        print("Stopped.")


def main():
    parser = argparse.ArgumentParser(
        description='Persistent PQC monitoring daemon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor default interface
  sudo ./persistent-monitor.py

  # Monitor specific interface
  sudo ./persistent-monitor.py --interface eth0

  # Custom output directory
  sudo ./persistent-monitor.py --output-dir /var/log/quantum-sniffer

  # Verbose output (show each connection)
  sudo ./persistent-monitor.py --verbose

Note: Requires root/sudo for packet capture.
"""
    )

    parser.add_argument(
        '-i', '--interface',
        help='Network interface to monitor (default: auto-detect)'
    )

    parser.add_argument(
        '-o', '--output-dir',
        default='/var/log/quantum-sniffer',
        help='Directory for log files (default: /var/log/quantum-sniffer)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show each connection on console (default: quiet)'
    )

    args = parser.parse_args()

    # Check for root
    if os.geteuid() != 0:
        print("Error: Packet capture requires root privileges", file=sys.stderr)
        print("Please run with: sudo ./persistent-monitor.py", file=sys.stderr)
        sys.exit(1)

    # Detect interface if not specified
    interface = args.interface or get_default_interface()

    try:
        monitor = PersistentMonitor(
            interface=interface,
            output_dir=args.output_dir,
            quiet=not args.verbose
        )
        monitor.start()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
