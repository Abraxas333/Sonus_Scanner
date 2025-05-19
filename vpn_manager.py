import subprocess
import time
import os
import signal
import asyncio


class VPNManager:
    def __init__(self, config_dir='/etc/openvpn/configs', max_connections=8):
        self.config_dir = config_dir
        self.max_connections = max_connections
        self.active_vpns = {}  # Process ID to interface mapping
        self.interface_status = {}  # Interface to status mapping

    async def start_vpn_connection(self, config_file, interface_num):
        """Start a VPN connection with a specific interface name"""
        interface_name = f"tun{interface_num}"
        log_file = f"/tmp/openvpn_{interface_name}.log"

        # Command to start OpenVPN with a specific interface name
        cmd = [
            'openvpn',
            '--config', os.path.join(self.config_dir, config_file),
            '--dev', interface_name,
            '--log', log_file
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Store process information
        self.active_vpns[process.pid] = {
            'interface': interface_name,
            'config': config_file,
            'process': process,
            'log_file': log_file
        }

        self.interface_status[interface_name] = {
            'status': 'connecting',
            'pid': process.pid,
            'config': config_file
        }

        # Wait for connection to establish (monitor log file)
        connected = await self._wait_for_connection(log_file)

        if connected:
            self.interface_status[interface_name]['status'] = 'connected'
            print(f"VPN connection established on {interface_name}")
            return interface_name
        else:
            self.interface_status[interface_name]['status'] = 'failed'
            print(f"Failed to establish VPN connection on {interface_name}")
            await self.stop_vpn_connection(process.pid)
            return None

    async def _wait_for_connection(self, log_file, timeout=30):
        """Monitor log file for successful connection"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        content = f.read()
                        if "Initialization Sequence Completed" in content:
                            return True
                except:
                    pass
            await asyncio.sleep(1)
        return False

    async def stop_vpn_connection(self, pid):
        """Stop a specific VPN connection by process ID"""
        if pid in self.active_vpns:
            vpn_info = self.active_vpns[pid]
            interface = vpn_info['interface']

            # Terminate the process
            try:
                vpn_info['process'].terminate()
                await vpn_info['process'].wait()
            except:
                # Force kill if terminate fails
                try:
                    os.kill(pid, signal.SIGKILL)
                except:
                    pass

            # Update status
            if interface in self.interface_status:
                self.interface_status[interface]['status'] = 'disconnected'

            # Remove from active VPNs
            del self.active_vpns[pid]
            print(f"VPN connection on {interface} terminated")
            return True
        return False

    async def start_multiple_vpns(self, configs):
        """Start multiple VPN connections in parallel"""
        tasks = []
        for i, config in enumerate(configs[:self.max_connections]):
            task = asyncio.create_task(self.start_vpn_connection(config, i))
            tasks.append(task)

        # Wait for all connections to establish
        interfaces = await asyncio.gather(*tasks)
        return [iface for iface in interfaces if iface]  # Filter out failed connections

    async def rotate_vpn(self, interface_name):
        """Rotate a specific VPN connection to a new server"""
        # Find the process ID for this interface
        pid = None
        for pid, info in self.active_vpns.items():
            if info['interface'] == interface_name:
                pid = pid
                break

        if pid:
            # Stop the current connection
            await self.stop_vpn_connection(pid)

            # Get a new config file (different from the current one)
            current_config = self.active_vpns.get(pid, {}).get('config')
            configs = [f for f in os.listdir(self.config_dir) if f.endswith('.ovpn') and f != current_config]

            if configs:
                # Start a new connection with the same interface number
                interface_num = int(interface_name.replace('tun', ''))
                new_config = random.choice(configs)
                return await self.start_vpn_connection(new_config, interface_num)

        return None

    def get_available_interface(self):
        """Get a currently connected interface for scanning"""
        available = [iface for iface, status in self.interface_status.items()
                     if status['status'] == 'connected']

        if available:
            return random.choice(available)
        return None

    def get_interface_status(self):
        """Get status of all interfaces"""
        return self.interface_status



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