"""Illumio PCE integration for labeling workloads with PQ status.

⚠️ WARNING: UNTESTED CODE
This module was implemented on 2026-06-25 but has not been tested against
a live Illumio PCE environment. It should work based on Illumio SDK docs,
but requires validation. Test in a non-production environment first.
"""

import os
import sys
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv

try:
    from illumio import PolicyComputeEngine, Label, IllumioApiException
    ILLUMIO_AVAILABLE = True
except ImportError:
    ILLUMIO_AVAILABLE = False


class IllumioIntegration:
    """Integration with Illumio PCE for PQ status labeling."""

    PQC_LABEL_KEY = 'pqc'
    PQC_VALUES = ['yes', 'hybrid', 'no', 'unknown']

    def __init__(self):
        """Initialize Illumio PCE connection."""
        if not ILLUMIO_AVAILABLE:
            raise ImportError(
                "illumio package not installed. "
                "Install with: pip install illumio"
            )

        load_dotenv()

        # Check required environment variables
        required = [
            'ILLUMIO_PCE_HOST',
            'ILLUMIO_API_KEY',
            'ILLUMIO_API_SECRET'
        ]
        missing = [var for var in required if not os.getenv(var)]
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}\n"
                "Set these in your .env file or environment."
            )

        # Create PCE client
        self.pce = PolicyComputeEngine(
            host=os.getenv('ILLUMIO_PCE_HOST'),
            port=int(os.getenv('ILLUMIO_PCE_PORT', 443)),
            org_id=int(os.getenv('ILLUMIO_ORG_ID', 1))
        )

        # Set credentials
        self.pce.set_credentials(
            api_key=os.getenv('ILLUMIO_API_KEY'),
            api_secret=os.getenv('ILLUMIO_API_SECRET')
        )

        # Verify connection
        try:
            self.pce.check_connection()
        except Exception as e:
            raise ConnectionError(f"Could not connect to PCE: {e}")

    def get_or_create_pqc_label(self, value: str) -> Label:
        """Get or create a PQC label with the given value.

        Args:
            value: Label value ('yes', 'hybrid', 'no', or 'unknown')

        Returns:
            Label object

        Raises:
            ValueError: If value is not valid
        """
        if value not in self.PQC_VALUES:
            raise ValueError(
                f"Invalid PQC label value: {value}. "
                f"Must be one of: {', '.join(self.PQC_VALUES)}"
            )

        # Try to get existing label
        labels = self.pce.labels.get(params={
            'key': self.PQC_LABEL_KEY,
            'value': value
        })

        if labels:
            return labels[0]

        # Create if doesn't exist
        return self.pce.labels.create(Label(
            key=self.PQC_LABEL_KEY,
            value=value
        ))

    def find_workload_by_ip(self, ip_address: str) -> Optional[Any]:
        """Find a workload by IP address.

        Args:
            ip_address: IP address to search for

        Returns:
            Workload object if found, None otherwise
        """
        # Search by interface IP
        workloads = self.pce.workloads.get(params={
            'ip_address': ip_address
        })

        if workloads:
            return workloads[0]

        # Also try public_ip
        workloads = self.pce.workloads.get(params={
            'public_ip': ip_address
        })

        if workloads:
            return workloads[0]

        return None

    def get_workload_pqc_label(self, workload: Any) -> Optional[str]:
        """Get the current PQC label value for a workload.

        Args:
            workload: Workload object

        Returns:
            PQC label value if set, None otherwise
        """
        if not workload.labels:
            return None

        for label_ref in workload.labels:
            # Get full label object
            label = self.pce.labels.get_by_reference(label_ref['href'])
            if label.key == self.PQC_LABEL_KEY:
                return label.value

        return None

    def update_workload_pqc_label(
        self,
        ip_address: str,
        pqc_value: str,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """Update PQC label for a workload identified by IP address.

        Args:
            ip_address: IP address of workload
            pqc_value: PQC status ('yes', 'hybrid', 'no', or 'unknown')
            dry_run: If True, don't actually update (default: False)

        Returns:
            Dict with status information

        Raises:
            ValueError: If workload not found or invalid pqc_value
        """
        # Find workload
        workload = self.find_workload_by_ip(ip_address)
        if not workload:
            raise ValueError(f"No workload found with IP address: {ip_address}")

        # Get current PQC label
        current_value = self.get_workload_pqc_label(workload)

        # Get or create the target PQC label
        pqc_label = self.get_or_create_pqc_label(pqc_value)

        # Build new labels list
        new_labels = []
        pqc_label_found = False

        if workload.labels:
            for label_ref in workload.labels:
                label = self.pce.labels.get_by_reference(label_ref['href'])
                if label.key == self.PQC_LABEL_KEY:
                    # Replace existing PQC label
                    new_labels.append({'href': pqc_label.href})
                    pqc_label_found = True
                else:
                    # Keep other labels
                    new_labels.append({'href': label.href})

        if not pqc_label_found:
            # Add PQC label if it didn't exist
            new_labels.append({'href': pqc_label.href})

        # Update workload
        if not dry_run:
            self.pce.workloads.update(workload.href, {'labels': new_labels})

        return {
            'ip_address': ip_address,
            'workload_name': workload.name,
            'workload_href': workload.href,
            'previous_value': current_value,
            'new_value': pqc_value,
            'action': 'updated' if not dry_run else 'dry_run'
        }

    def initialize_all_workloads_pqc_unknown(
        self,
        force: bool = False,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """Initialize all workloads without a PQC label to 'unknown'.

        This is a bulk operation that should be run with caution.

        Args:
            force: Required to be True to actually run
            dry_run: If True, don't actually update (default: False)

        Returns:
            Dict with operation statistics

        Raises:
            ValueError: If force is not True
        """
        if not force:
            raise ValueError(
                "This operation will modify all workloads without a PQC label. "
                "Set force=True to proceed."
            )

        # Get all workloads
        all_workloads = self.pce.workloads.get()

        # Get or create 'unknown' label
        unknown_label = self.get_or_create_pqc_label('unknown')

        # Find workloads without PQC label
        workloads_to_update = []
        for workload in all_workloads:
            current_pqc = self.get_workload_pqc_label(workload)
            if current_pqc is None:
                workloads_to_update.append(workload)

        if not dry_run:
            # Bulk update for efficiency
            updates = []
            for workload in workloads_to_update:
                # Build labels list: keep existing + add pqc=unknown
                new_labels = []
                if workload.labels:
                    new_labels = [{'href': label_ref['href']}
                                  for label_ref in workload.labels]
                new_labels.append({'href': unknown_label.href})

                updates.append({
                    'href': workload.href,
                    'labels': new_labels
                })

            # Bulk update (more efficient than individual updates)
            if updates:
                self.pce.workloads.bulk_update(updates)

        return {
            'total_workloads': len(all_workloads),
            'workloads_without_pqc': len(workloads_to_update),
            'workloads_updated': len(workloads_to_update) if not dry_run else 0,
            'action': 'completed' if not dry_run else 'dry_run',
            'workloads': [
                {
                    'name': w.name,
                    'href': w.href,
                    'hostname': w.hostname if hasattr(w, 'hostname') else None,
                    'ip_addresses': [iface.address for iface in (w.interfaces or [])
                                     if hasattr(iface, 'address')]
                }
                for w in workloads_to_update
            ]
        }

    def get_workload_summary(self) -> Dict[str, Any]:
        """Get summary of PQC labeling across all workloads.

        Returns:
            Dict with counts and statistics
        """
        all_workloads = self.pce.workloads.get()

        summary = {
            'total': len(all_workloads),
            'by_pqc_status': {
                'yes': 0,
                'hybrid': 0,
                'no': 0,
                'unknown': 0,
                'not_labeled': 0
            },
            'workloads': []
        }

        for workload in all_workloads:
            pqc_value = self.get_workload_pqc_label(workload)

            if pqc_value is None:
                summary['by_pqc_status']['not_labeled'] += 1
            elif pqc_value in summary['by_pqc_status']:
                summary['by_pqc_status'][pqc_value] += 1

            # Get IP addresses
            ip_addresses = []
            if hasattr(workload, 'interfaces') and workload.interfaces:
                ip_addresses = [iface.address for iface in workload.interfaces
                                if hasattr(iface, 'address') and iface.address]
            if hasattr(workload, 'public_ip') and workload.public_ip:
                ip_addresses.append(workload.public_ip)

            summary['workloads'].append({
                'name': workload.name,
                'hostname': workload.hostname if hasattr(workload, 'hostname') else None,
                'ip_addresses': ip_addresses,
                'pqc_status': pqc_value or 'not_labeled'
            })

        return summary
