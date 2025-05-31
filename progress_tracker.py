import json
import os
from typing import Dict, List


class ProgressTracker:
    # Define scan types as powers of 2 (each gets a unique bit)
    SCAN_TYPES = {
        'liveness': 1,  # 2^0 = 1   (bit 0)
        'waf': 2,  # 2^1 = 2   (bit 1)
        'subdomain': 4,  # 2^2 = 4   (bit 2)
        'port_scan': 8,  # 2^3 = 8   (bit 3)
        'ssl_scan': 16,  # 2^4 = 16  (bit 4)
        'dir_enum': 32,  # 2^5 = 32  (bit 5)
        # Add more scan types as needed, each as next power of 2
    }

    # Special status values
    DEAD_DOMAIN = -1
    FULLY_COMPLETE = sum(SCAN_TYPES.values())  # All bits set

    def __init__(self, progress_file="scan_progress.json"):
        self.progress_file = progress_file
        self.progress: Dict[str, int] = {}  # domain -> bitmap
        self.load_progress()

    def load_progress(self):
        """Load progress from file"""
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, 'r') as f:
                    self.progress = json.load(f)
                print(f"Loaded progress for {len(self.progress)} domains")
            except Exception as e:
                print(f"Error loading progress: {e}")
                self.progress = {}
        else:
            self.progress = {}

    def save_progress(self):
        """Save progress to file"""
        try:
            with open(self.progress_file, 'w') as f:
                json.dump(self.progress, f, indent=2)
        except Exception as e:
            print(f"Error saving progress: {e}")

    def should_skip_domain(self, domain: str) -> bool:
        """Check if domain should be skipped (dead or fully complete)"""
        domain_status = self.progress.get(domain, 0)
        return (domain_status == self.DEAD_DOMAIN or
                domain_status == self.FULLY_COMPLETE)

    def is_domain_dead(self, domain: str) -> bool:
        """Check if domain is marked as dead"""
        return self.progress.get(domain, 0) == self.DEAD_DOMAIN

    def mark_domain_dead(self, domain: str):
        """Mark domain as dead (not live)"""
        self.progress[domain] = self.DEAD_DOMAIN
        self.save_progress()
        print(f"Marked {domain} as dead")

    def is_scan_complete(self, domain: str, scan_type: str) -> bool:
        """Check if specific scan is complete for domain"""
        if scan_type not in self.SCAN_TYPES:
            raise ValueError(f"Unknown scan type: {scan_type}")

        domain_status = self.progress.get(domain, 0)

        # Dead domains are considered "complete" (skip all scans)
        if domain_status == self.DEAD_DOMAIN:
            return True

        # Check if the specific scan bit is set
        return bool(domain_status & self.SCAN_TYPES[scan_type])

    def mark_scan_complete(self, domain: str, scan_type: str):
        """Mark specific scan as complete"""
        if scan_type not in self.SCAN_TYPES:
            raise ValueError(f"Unknown scan type: {scan_type}")

        # Don't modify dead domains
        if self.progress.get(domain, 0) == self.DEAD_DOMAIN:
            return

        # Initialize domain if not exists
        if domain not in self.progress:
            self.progress[domain] = 0

        # Set the bit for this scan type
        self.progress[domain] |= self.SCAN_TYPES[scan_type]

        print(f"Marked {scan_type} complete for {domain} (status: {self.progress[domain]})")
        self.save_progress()

    def get_remaining_scans(self, domain: str) -> List[str]:
        """Get list of incomplete scans for domain"""
        domain_status = self.progress.get(domain, 0)

        # Dead domains have no remaining scans
        if domain_status == self.DEAD_DOMAIN:
            return []

        # Find scans that aren't complete
        remaining = []
        for scan_type, bit_value in self.SCAN_TYPES.items():
            if not (domain_status & bit_value):
                remaining.append(scan_type)

        return remaining

    def get_completion_status(self, domain: str) -> dict:
        """Get detailed completion status for domain"""
        domain_status = self.progress.get(domain, 0)

        if domain_status == self.DEAD_DOMAIN:
            return {"status": "dead", "completed_scans": [], "remaining_scans": []}

        completed = []
        remaining = []

        for scan_type, bit_value in self.SCAN_TYPES.items():
            if domain_status & bit_value:
                completed.append(scan_type)
            else:
                remaining.append(scan_type)

        status = "complete" if not remaining else "partial" if completed else "not_started"

        return {
            "status": status,
            "completed_scans": completed,
            "remaining_scans": remaining,
            "bitmap_value": domain_status
        }

    def get_domains_to_process(self, all_domains: List[str]) -> List[str]:
        """Filter domains to only those needing processing"""
        return [domain for domain in all_domains
                if not self.should_skip_domain(domain)]

    def print_progress_summary(self):
        """Print a summary of current progress"""
        if not self.progress:
            logging.info("No progress data found")
            return

        dead_count = sum(1 for status in self.progress.values() if status == self.DEAD_DOMAIN)
        complete_count = sum(1 for status in self.progress.values() if status == self.FULLY_COMPLETE)
        partial_count = len(self.progress) - dead_count - complete_count

        logging.info(f"\nProgress Summary:")
        logging.info(f"  Total domains tracked: {len(self.progress)}")
        logging.info(f"  Dead domains: {dead_count}")
        logging.info(f"  Fully complete: {complete_count}")
        logging.info(f"  Partially complete: {partial_count}")

        # Show some examples of partial domains
        if partial_count > 0:
            print(f"\nPartial domains (showing first 5):")
            count = 0
            for domain, status in self.progress.items():
                if status not in [self.DEAD_DOMAIN, self.FULLY_COMPLETE] and count < 5:
                    completion = self.get_completion_status(domain)
                    logging.info(f"  {domain}: {completion['completed_scans']}")
                    count += 1


# Example usage:
if __name__ == "__main__":
    tracker = ProgressTracker()

    # Example operations
    tracker.mark_scan_complete("example.com", "liveness")
    tracker.mark_scan_complete("example.com", "waf")

    logging.info(f"Liveness complete? {tracker.is_scan_complete('example.com', 'liveness')}")
    logging.info(f"Port scan complete? {tracker.is_scan_complete('example.com', 'port_scan')}")
    logging.info(f"Remaining scans: {tracker.get_remaining_scans('example.com')}")

    tracker.mark_domain_dead("dead-domain.com")
    logging.info(f"Should skip dead domain? {tracker.should_skip_domain('dead-domain.com')}")

    tracker.print_progress_summary()