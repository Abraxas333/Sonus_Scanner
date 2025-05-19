import subprocess
import time
import os
import signal
import asyncio


class ScanCoordinator:
    def __init__(self, vpn_configs, domains, output_base_dir):
        self.vpn_manager = VPNManager()
        self.domains = domains
        self.output_base_dir = output_base_dir
        self.vpn_configs = vpn_configs
        self.domain_status = {}
        self.scanners = {}

    async def initialize(self):
        """Initialize VPN connections and prepare for scanning"""
        # Start multiple VPN connections
        self.active_interfaces = await self.vpn_manager.start_multiple_vpns(self.vpn_configs)
        print(f"Established {len(self.active_interfaces)} VPN connections")

    async def run_scans(self):
        """Run scans across multiple VPN interfaces"""
        # Create a queue of domains to scan
        domain_queue = asyncio.Queue()
        for domain in self.domains:
            await domain_queue.put(domain)

        # Create scanner tasks for each interface
        scanner_tasks = []
        for interface in self.active_interfaces:
            task = asyncio.create_task(self.scan_worker(interface, domain_queue))
            scanner_tasks.append(task)

        # Wait for all domains to be scanned
        await domain_queue.join()

        # Cancel scanner tasks
        for task in scanner_tasks:
            task.cancel()

        # Wait for tasks to be cancelled
        await asyncio.gather(*scanner_tasks, return_exceptions=True)

    async def scan_worker(self, interface, domain_queue):
        """Worker that takes domains from queue and scans them"""
        while True:
            try:
                domain = await domain_queue.get()

                # Create a scanner for this domain using the assigned interface
                scanner = AsyncScanner(domain,
                                       output_dir=os.path.join(self.output_base_dir, domain.replace('.', '_')),
                                       interface=interface)

                # Start the traffic monitor for this scanner
                await scanner.start_traffic_monitor()

                # Track active scanner
                self.scanners[domain] = {
                    'scanner': scanner,
                    'interface': interface,
                    'status': 'scanning'
                }

                # Run the scan
                try:
                    # Check liveness first
                    liveness = await scanner.check_liveness()

                    if liveness.get('is_live', False):
                        # Run full scan if domain is live
                        await scanner.run_full_scan_async()
                    else:
                        print(f"Domain {domain} is not live, skipping scan")

                    self.scanners[domain]['status'] = 'completed'

                except Exception as e:
                    print(f"Error scanning {domain}: {str(e)}")
                    self.scanners[domain]['status'] = 'error'

                # Stop the traffic monitor
                await scanner.stop_traffic_monitor()

                # Mark task as done
                domain_queue.task_done()

            except asyncio.CancelledError:
                break