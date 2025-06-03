# scanner.py - Scanner with fixed logging
import yaml
import os
import sys
import json
import asyncio
import socket
import fcntl
import struct
import re
import aiohttp
import random
import multiprocessing as mp
import subprocess as sp
import logging
import time
import socket
from functools import partial
from datetime import datetime
from waf_signatures import get_signatures
from mutations import generate_mutations
from scapy.all import *
from scapy.layers.inet import IP, TCP, raw
from scapy.modules.nmap import nmap_match_one_sig

# Create logger for this module
logger = logging.getLogger(__name__)


class AsyncScanner:
    VPN_CONFIGS = []

    def __init__(self, target, output_dir, interface):
        self.target = target
        self.output_dir = output_dir
        self.interface = interface
        self.active_vpn = {}
        self.current_pid = None
        self.results = {}
        self.blocked = False
        self.active_scans = {}
        self.target_ip = None
        self.waf_block_event = asyncio.Event()
        self.packet_count = 0
        self.waf_block_count = 0
        self.waf_type = "unknown"
        self.matched_signature = None

        # Load VPN configs if not already loaded
        if not self.VPN_CONFIGS:
            try:
                self.VPN_CONFIGS = [f for f in os.listdir('/var/www/recon/vpn_configs') if f.endswith('.ovpn')]
            except Exception as e:
                logger.error(f"Error loading VPN configs: {e}")
                self.VPN_CONFIGS = []

    # check if domain is a wildcard (*.example.com) or standard (example.com)
    async def run(self):
        try:
            logger.info(f"Starting scan for target: {self.target}")
            await self.start_vpn_connection()
            await self.start_traffic_monitor()

            if '*' in self.target:
                await self.enumerate_subdomains()
            else:
                await self.enumerate_domain()

            logger.info(f"Completed scan for target: {self.target}")
        except Exception as e:
            logger.error(f"Error in run() for {self.target}: {str(e)}", exc_info=True)
            raise

    async def enumerate_domain(self):
        try:
            logger.info(f"Enumerating domain: {self.target}")
            is_live = await self.check_liveness()
            if is_live:
                await self.sniff_waf()
            else:
                logger.info(f"Domain {self.target} is not live, skipping further enumeration")
        except Exception as e:
            logger.error(f"Error in enumerate_domain for {self.target}: {str(e)}", exc_info=True)

    # helper methods
    def _register_tool(self, tool):
        task_id = id(asyncio.current_task())
        self.active_scans[task_id] = tool
        logger.debug(f"Registered tool {tool} with task_id {task_id}")
        return task_id

    def _unregister_tool(self, task_id):
        if task_id in self.active_scans:
            tool = self.active_scans[task_id]
            del self.active_scans[task_id]
            logger.debug(f"Unregistered tool {tool} with task_id {task_id}")

    def get_active_tools(self):
        return list(self.active_scans.values())

    # run amass on wildcard domains and create directories for each found subdomain
    async def enumerate_subdomains(self):
        domain_dir = os.path.join(self.output_dir, self.target.replace('*', 'wildcard'))
        os.makedirs(domain_dir, exist_ok=True)
        self.output_dir = domain_dir

        # strip the asterisk from the target and format the target into a wildcard domain dir name
        stripped_domain = self.target.replace('*', '')
        # start amass subdomain enumeration
        task_id = self._register_tool('amass')

        # refactor outputfile to json file
        amass_output_file = os.path.join(domain_dir, 'subdomains.txt')
        cmd = ['amass', 'enum', '-d', stripped_domain, '-o', amass_output_file]

        try:
            logger.info(f"Running amass for domain: {stripped_domain}")
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                with open(amass_output_file, 'r') as f:
                    subdomains_found = [line.strip() for line in f.readlines() if line.strip()]

                if subdomains_found:
                    logger.info(f"Found {len(subdomains_found)} subdomains for {stripped_domain}")
                    subdomain_tasks = []
                    for subdomain in subdomains_found:
                        task = asyncio.create_task(self._scan_subdomain(subdomain, domain_dir))
                        subdomain_tasks.append(task)

                    # Process all subdomains concurrently
                    results = await asyncio.gather(*subdomain_tasks, return_exceptions=True)
                    logger.info(f"Completed scanning {len(subdomains_found)} subdomains")
                else:
                    logger.info(f"No subdomains found for {stripped_domain}")
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Amass failed with return code {process.returncode}: {error_msg}")

        except Exception as e:
            logger.error(f"Error during subdomain enumeration: {str(e)}", exc_info=True)

        finally:
            self._unregister_tool(task_id)

    async def _scan_subdomain(self, subdomain, base_dir):
        """Scan a single subdomain with isolated state"""
        # Save original state
        original_target = self.target
        original_output_dir = self.output_dir

        try:
            logger.info(f"Scanning subdomain: {subdomain}")
            # Set subdomain as target
            self.target = subdomain
            self.output_dir = base_dir  # Will be updated by check_liveness if live

            # Run standard domain enumeration
            await self.enumerate_domain()

        except Exception as e:
            logger.error(f"Error scanning subdomain {subdomain}: {str(e)}", exc_info=True)
        finally:
            # Restore original state
            self.target = original_target
            self.output_dir = original_output_dir

    async def check_liveness(self):
        # Set tool
        task_id = self._register_tool('dig')

        try:
            # This automatically handles CNAMEs and returns the final IP
            ip = socket.gethostbyname(self.target)
            self.target_ip = ip

            # Domain is live - create directory if needed
            domain_dir = os.path.join(self.output_dir, self.target)
            os.makedirs(domain_dir, exist_ok=True)
            self.output_dir = domain_dir

            # set target_ip attribute
            self.target_ip = ip_addresses[0]
            logger.info(f"Domain {self.target} resolved to IP: {self.target_ip}")

            # Get nameservers
            ns_cmd = ['dig', 'NS', self.target, '+short']
            ns_process = await asyncio.create_subprocess_exec(
                *ns_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            ns_stdout, ns_stderr = await ns_process.communicate()
            nameservers = []

            if ns_stdout:
                nameservers = [ns.strip() for ns in ns_stdout.decode().strip().split('\n') if ns.strip()]

            # Create result dictionary
            result = {
                "domain": self.target,
                "is_live": True,
                "url": f"http://{self.target}",
                "https_url": f"https://{self.target}",
                "ip_addresses": ip_addresses,
                "ip": ip_addresses[0] if ip_addresses else None,
                "nameservers": nameservers,
                "timestamp": datetime.now().isoformat(),
                "command": " ".join(cmd)
            }

            # Save results to file
            result_file = os.path.join(domain_dir, "live_domain_data.json")
            with open(result_file, 'w') as f:
                json.dump(result, f, indent=2)

            # Store in results dictionary
            self.results[self.active_scans.get(task_id)] = result

            logger.info(f"Domain {self.target} is live with {len(ip_addresses)} IP addresses")
            return True

        except socket.gaierror:
            # Domain doesn't resolve
            logger.info(f"Domain {self.target} is not live (no A records)")
            return False

        finally:
            self._unregister_tool(task_id)

    async def sniff_waf(self, custom_headers=False, headers_file=None):
        task_id = self._register_tool("wafw00f")
        result_file = os.path.join(self.output_dir, "waf.json")
        log_file = os.path.join(self.output_dir, "waf_log.json")

        try:
            logger.info(f"Starting WAF detection for {self.target}")
            cmd = ['/usr/bin/wafw00f', f'http://{self.target}', '-a', '-f', 'json', '-o', result_file, '-vvv']

            if custom_headers and headers_file:
                if os.path.exists(headers_file):
                    cmd.extend(['-H', headers_file])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PYTHONUNBUFFERED": "1"}
            )
            stdout, stderr = await process.communicate()
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')

            full_output = stdout_text + stderr_text

            # Parse useful information from the verbose output
            parsed_log = {
                "timestamp": datetime.now().isoformat(),
                "command": " ".join(cmd),
                "debug_messages": [],
                "info_messages": [],
                "request_details": [],
                "headers": {},
                "content_sample": None,
                "detection_results": []
            }

            # Parse out the interesting information with regex
            for line in full_output.splitlines():
                # Strip ANSI codes
                clean_line = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', line)

                # Capture DEBUG messages
                if clean_line.startswith("DEBUG:"):
                    parsed_log["debug_messages"].append(clean_line)

                    # Extract headers if present
                    if "Headers:" in clean_line:
                        try:
                            headers_part = clean_line.split("Headers:", 1)[1].strip()
                            # Convert string representation of dict to actual dict
                            parsed_log["headers"] = eval(headers_part)
                        except:
                            parsed_log["headers"] = {"raw": headers_part}

                    # Extract content sample if present
                    elif "Content:" in clean_line:
                        content_part = clean_line.split("Content:", 1)[1].strip()
                        parsed_log["content_sample"] = content_part[:500] + "..." if len(
                            content_part) > 500 else content_part

                # Capture INFO messages
                elif clean_line.startswith("INFO:"):
                    parsed_log["info_messages"].append(clean_line)

                # Capture detection results
                elif clean_line.startswith("[*]") or clean_line.startswith("[+]") or clean_line.startswith("[~]"):
                    parsed_log["detection_results"].append(clean_line)

            # Read the wafw00f output file for structured results
            waf_data = {"detected": False}
            if os.path.exists(result_file) and os.path.getsize(result_file) > 0:
                try:
                    with open(result_file, 'r') as f:
                        waf_data = json.load(f)
                except Exception as e:
                    logger.error(f"Error reading WAF result file: {e}")
            result = {}
            if isinstance(waf_data, dict):
            # Merge parsed log with WAF detection results
                result = {
                    "timestamp": datetime.now().isoformat(),
                    "command": " ".join(cmd),
                    "waf_detected": waf_data.get("detected", False),
                    "firewall": waf_data.get("firewall"),
                    "manufacturer": waf_data.get("manufacturer"),
                    "url": waf_data.get("url"),
                    "raw_data": waf_data,
                    "parsed_output": parsed_log,
                    "request_count": len([m for m in parsed_log["debug_messages"] if "Request Succeeded" in m])
                }
            elif isinstance(waf_data, list):
                result = {
                    "timestamp": datetime.now().isoformat(),
                    "command": " ".join(cmd),
                    "waf_detected": [x.get("detected") for x in waf_data],
                    "firewall": [x.get("firewall") for x in waf_data],
                    "manufacturer": [x.get("manufacturer") for x in waf_data],
                    "url": waf_data.get("url"),
                    "raw_data": waf_data,
                    "parsed_output": parsed_log,
                    "request_count": len([m for m in parsed_log["debug_messages"] if "Request Succeeded" in m])
                }

            # Extract specific details for easier access
            reasons = [line for line in parsed_log["detection_results"] if "Reason:" in line]
            if reasons:
                result["blocking_reason"] = reasons[0].split("Reason:", 1)[1].strip()

            # Save the structured log
            with open(log_file, 'w') as f:
                json.dump(result, f, indent=2)

            # Store in results dictionary
            self.results["wafw00f"] = result

            logger.info(f"Completed WAF detection for {self.target}")
            if result.get("waf_detected"):
                logger.info(f"WAF detected: {result.get('firewall', 'Unknown')}")
                self.waf_type = result.get('firewall', 'unknown').lower()

            return result

        except Exception as e:
            error_result = {
                "timestamp": datetime.now().isoformat(),
                "command": ' '.join(cmd) if 'cmd' in locals() else "unknown",
                "error": str(e),
                "waf_detected": False
            }

            # Save error result
            with open(log_file, 'w') as f:
                json.dump(error_result, f, indent=2)

            self.results["wafw00f"] = error_result
            logger.error(f"Error in WAF detection for {self.target}: {str(e)}", exc_info=True)
            return error_result

        finally:
            self._unregister_tool(task_id)

    async def test_waf_bypass(self):
        task_id = self._register_tool("vegeta")
        result_file = os.path.join(self.output_dir, "waf_bypass.json")
        log_file = os.path.join(self.output_dir, "waf_bypass_log.json")
        rates = [50, 100, 200, 500, 1000]

        try:
            logger.info(f"Starting WAF bypass testing for {self.target}")
            await self.start_vpn_connection()
            await self.start_traffic_monitor()

            while not self.waf_block_event.is_set():
                for rate in rates:
                    vegeta_cmd = f"echo 'GET https://{self.target_ip}' | /usr/bin/vegeta attack -duration=5s -rate={rate} -max-workers={int(rate / 10)} | /usr/bin/vegeta report"
                    cmd = ['sudo', '-u', 'recon_user', 'bash', '-c', vegeta_cmd]

                    process = await asyncio.create_subprocess_exec(
                        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

                    stdout, stderr = await process.communicate()
                    stdout_text = stdout.decode('utf-8', errors='replace')
                    stderr_text = stderr.decode('utf-8', errors='replace')

                    logger.debug(f"Vegeta output for rate {rate}: {stdout_text}")

            if self.waf_block_event.is_set():
                logger.info("WAF block detected, testing bypass mutations")
                payload = f"GET https://{self.target}"
                for name, value, metadata in generate_mutations(payload, self.waf_type):
                    if metadata.get("headers"):
                        # Test with special headers
                        success = await self.test_with_headers(value, metadata["headers"])
                    else:
                        # Test with just the mutated path
                        success = await self.test_mutation(value)

                    if success:
                        logger.info(f"Bypass found: {name}")
                        break

        except Exception as e:
            logger.error(f"Error in WAF bypass testing for {self.target}: {str(e)}", exc_info=True)
        finally:
            self._unregister_tool(task_id)

    async def test_with_headers(self, value, headers):
        # Placeholder for testing with headers
        logger.debug(f"Testing mutation with headers: {headers}")
        return False

    async def test_mutation(self, value):
        # Placeholder for testing mutation
        logger.debug(f"Testing mutation: {value}")
        return False

    def scan_ports(self):
        pass

    def tech_detect(self):
        pass

    def ffufw_scan(self):
        pass

    def nuclei_scan(self):
        pass

    def http_parameters(self):
        pass

    def metasploit_scan(self):
        pass

    ######### VPN CONNECTION AND ROTATION #########

    async def start_vpn_connection(self):
        """Start a VPN connection with a specific interface name"""
        logger.info(f"Starting VPN connection on interface {self.interface}")

        existing_ip = await self.get_ip_address()
        if existing_ip:
            logger.info(f"VPN already active on {self.interface} with IP {existing_ip}")
            self.active_vpn[0] = {  # Use dummy PID
                'interface': self.interface,
                'status': 'connected',
                'ip': existing_ip
            }
            return True
        # Get list of already used IPs
        used_ips = [vpn_info['ip'] for vpn_info in self.active_vpn.values() if 'ip' in vpn_info]
        new_ip = False
        attempts = 0
        max_attempts = 10

        while not new_ip and attempts < max_attempts:
            attempts += 1
            log_file = f"/tmp/openvpn_{self.interface}.log"

            if not self.VPN_CONFIGS:
                logger.error("No VPN configurations available")
                return False

            config_file = os.path.join('/var/www/recon/vpn_configs', random.choice(self.VPN_CONFIGS))
            logger.info(f"Attempting VPN connection with config: {config_file}")

            # Start OpenVPN
            cmd = [
                'openvpn',
                '--config', config_file,
                '--dev', self.interface,
                '--log', log_file
            ]

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                self.current_pid = process.pid

                # Store initial process information
                self.active_vpn[process.pid] = {
                    'config': config_file,
                    'process': process,
                    'log_file': log_file,
                    'interface': self.interface,
                    'status': 'connecting'
                }

                # Wait for connection to establish
                connected = await self._wait_for_connection(log_file)

                if connected:
                    # NOW get the IP address after connection is established
                    ip = await self.get_ip_address()

                    if ip and ip not in used_ips:
                        # Success - new IP
                        self.active_vpn[self.current_pid]['status'] = 'connected'
                        self.active_vpn[self.current_pid]['ip'] = ip
                        logger.info(f"VPN connection established on {self.interface} with IP {ip}")
                        new_ip = True
                        return True
                    else:
                        logger.warning(f"IP {ip} already used or invalid, trying another VPN")
                        process.terminate()
                        await process.wait()
                else:
                    logger.warning(f"VPN connection failed on attempt {attempts}")
                    process.terminate()
                    await process.wait()

            except Exception as e:
                logger.error(f"Error starting VPN: {str(e)}", exc_info=True)
                if 'process' in locals():
                    try:
                        process.terminate()
                        await process.wait()
                    except:
                        pass

        logger.error(f"Failed to establish VPN connection after {max_attempts} attempts")
        return False

    async def get_ip_address(self):
        """
        Return the IPv4 address assigned to the interface.
        Returns None if the interface doesn't exist or has no IPv4 address.
        """
        try:
            # Create a dummy socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # SIOCGIFADDR = 0x8915: "get interface address"
            iface_bytes = struct.pack('256s', self.interface.encode('utf-8')[:15])
            res = fcntl.ioctl(sock.fileno(), 0x8915, iface_bytes)
            # bytes 20–24 of the result contain the IPv4 address
            ip = struct.unpack('!I', res[20:24])[0]
            return socket.inet_ntoa(struct.pack('!I', ip))
        except OSError as e:
            logger.error(f"Failed to get IP for {self.interface}: {e}")
            return None

    async def _wait_for_connection(self, log_file, timeout=30):
        """Monitor log file for successful connection"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if os.path.exists(log_file):
                try:
                    result = await asyncio.create_subprocess_exec(
                        'tail', '-5', log_file,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await result.communicate()
                    if b"Initialization Sequence Completed" in stdout:
                        # Give it a moment for the interface to fully come up
                        await asyncio.sleep(1)
                        return True
                except Exception as e:
                    logger.debug(f"Error reading VPN log file: {e}")
            await asyncio.sleep(1)
        return False

    async def stop_vpn(self):
        """Stop the current VPN connection"""
        if not self.current_pid or self.current_pid not in self.active_vpn:
            logger.warning("No active VPN to stop")
            return False

        vpn_info = self.active_vpn[self.current_pid]
        process = vpn_info['process']

        try:
            logger.info(f"Stopping VPN on {vpn_info.get('interface', 'unknown')}")
            process.terminate()
            await process.wait()
            logger.info(f"VPN stopped on {vpn_info.get('interface', 'unknown')}")
        except:
            try:
                process.kill()
                await process.wait()
            except Exception as e:
                logger.error(f"Failed to stop VPN: {e}")
                return False

        self.active_vpn[self.current_pid]['status'] = 'stopped'
        self.current_pid = None
        return True

    async def rotate_vpn(self):
        """Rotate to a new VPN connection"""
        logger.info(f"Rotating VPN for {self.target}")
        await self.stop_vpn()
        await asyncio.sleep(2)  # Brief pause between connections
        return await self.start_vpn_connection()

    ######### MONITORING AND WAF DETECTION #########

    async def start_traffic_monitor(self):
        """Start monitoring traffic for WAF blocks"""
        self.stop_monitoring = False
        self.packet_count = 0
        self.waf_block_count = 0

        # Start the monitoring in a separate thread to not block asyncio
        self.monitor_task = asyncio.create_task(self._run_traffic_monitor())
        logger.info(f"Traffic monitoring started for {self.target} on {self.interface}")

    async def stop_traffic_monitor(self):
        """Stop the traffic monitoring"""
        self.stop_monitoring = True
        if hasattr(self, 'monitor_task') and self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        logger.info(f"Traffic monitoring stopped for {self.target}")

    async def _run_traffic_monitor(self):
        """Run the traffic monitoring in a way that doesn't block asyncio"""
        # This runs the monitor in an executor to not block the event loop
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, self._monitor_traffic)
        except Exception as e:
            logger.error(f"Error in traffic monitor: {str(e)}", exc_info=True)

    def _monitor_traffic(self):
        """Monitor traffic for WAF blocks using Scapy"""
        pcap_file = os.path.join(self.output_dir, f"{self.target}_traffic.pcap")
        blocks_pcap_file = os.path.join(self.output_dir, f"{self.target}_traffic_blocks.pcap")

        # Define WAF block signatures
        waf_signatures = get_signatures()

        if not waf_signatures:
            logger.warning("No WAF signatures loaded. Monitoring will be limited.")

        # Start capturing packets
        def packet_callback(packet):
            if self.stop_monitoring:
                return

            # Check if the packet is related to our target
            if IP in packet and TCP in packet:
                # Only look at packets to/from our target
                if packet[IP].src == self.target_ip or packet[IP].dst == self.target_ip:

                    # save all packets to pcap_file and count packets
                    wrpcap(pcap_file, [packet], append=True)
                    self.packet_count += 1

                    # Check packet against WAF signatures
                    if self._check_waf_block(packet, waf_signatures):
                        logger.info(f"WAF BLOCK DETECTED for {self.target}")
                        self.blocked = True
                        self.waf_block_event.set()
                        # save the block indicating packets separately
                        wrpcap(blocks_pcap_file, [packet], append=True)
                        self.waf_block_count += 1

                        # Log which signature matched
                        with open(os.path.join(self.output_dir, "waf_block_detail.txt"), "a") as f:
                            f.write(f"WAF block detected at {datetime.now().isoformat()}\n")
                            f.write(f"Target: {self.target}\n")
                            f.write(f"Source IP: {packet[IP].src}\n")
                            f.write(f"Dest IP: {packet[IP].dst}\n")
                            f.write(f"Source Port: {packet[TCP].sport}\n")
                            f.write(f"Dest Port: {packet[TCP].dport}\n")
                            f.write(str(packet.show(dump=True)))

                            if hasattr(self, 'matched_signature'):
                                f.write(f"Matched signature: {self.matched_signature}\n")

                        # Notify for VPN rotation if needed
                        logger.info(f"VPN rotation needed for {self.interface}")

        # Start the capture on the specific interface
        try:
            # Filter for TCP traffic to/from our target IP
            if self.target_ip:
                bpf_filter = f"host {self.target_ip} and tcp"
            else:
                logger.warning("No target IP set, monitoring all TCP traffic")
                bpf_filter = "tcp"

            logger.info(f"Starting packet capture on {self.interface} with filter: {bpf_filter}")

            # Use Scapy's sniff function
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=packet_callback,
                store=0,  # Don't store packets in memory
                stop_filter=lambda p: self.stop_monitoring  # Stop when flagged
            )
        except Exception as e:
            logger.error(f"Error in traffic capture: {str(e)}", exc_info=True)

    def _check_waf_block(self, packet, signatures):
        """Check if a packet matches any WAF block signatures"""
        try:
            # Layer 3 check
            if IP in packet:
                original_dst = packet[IP].dst
                response_src = packet[IP].src
                if self.target_ip and response_src != self.target_ip and original_dst == self.target_ip:
                    # Response from different IP than requested
                    self.matched_signature = f"IP source mismatch: {response_src} != {self.target_ip}"
                    return True

            # Layer 4 check
            if TCP in packet:
                if packet[TCP].flags & 0x04:  # RST flag
                    self.matched_signature = "TCP RST flag"
                    return True

            # Initialize HTTP data extraction (will be done only if needed)
            http_data = None

            for sig in signatures:
                sig_type = sig.get('type', '')
                match = False

                # Layer-specific signatures (TCP)
                if sig_type == 'layer_field':
                    layer_name = sig.get('layer')
                    field = sig.get('field')
                    value = sig.get('value')

                    # Handle different layer types
                    layer = None
                    if layer_name == 'TCP' or layer_name is TCP:
                        layer = TCP
                    elif layer_name == 'IP' or layer_name is IP:
                        layer = IP

                    if layer and layer in packet and hasattr(packet[layer], field):
                        if getattr(packet[layer], field) == value:
                            match = True
                            self.matched_signature = f"TCP field {field}={value}"

                # HTTP-based signatures (require extracting HTTP data)
                elif sig_type in ['header', 'header_regex', 'content', 'content_regex', 'status_code']:
                    # Extract HTTP data if not already done
                    if http_data is None:
                        http_data = self._extract_http_data(packet)

                    if not http_data:
                        continue  # Skip HTTP checks if not HTTP data

                    # Check header signatures
                    if sig_type == 'header' and 'name' in sig:
                        header_name = sig['name'].lower()
                        if any(h.lower() == header_name for h in http_data.get('headers', {})):
                            match = True
                            self.matched_signature = f"Header: {sig['name']}"

                    # Check header regex patterns
                    elif sig_type == 'header_regex' and 'pattern' in sig:
                        pattern = sig['pattern']
                        for header in http_data.get('headers', {}):
                            if re.search(pattern, header, re.IGNORECASE):
                                match = True
                                self.matched_signature = f"Header pattern: {pattern}"
                                break

                    # Check content signatures
                    elif sig_type == 'content' and 'text' in sig:
                        text = sig['text']
                        if text in http_data.get('body', b''):
                            match = True
                            self.matched_signature = f"Content: {text[:30]}..."

                    # Check content regex patterns
                    elif sig_type == 'content_regex' and 'pattern' in sig:
                        pattern = sig.get('compiled_pattern', re.compile(sig['pattern'].encode('utf-8')))
                        if pattern.search(http_data.get('body', b'')):
                            match = True
                            self.matched_signature = f"Content pattern: {sig['pattern'][:30]}..."

                    # Check status codes
                    elif sig_type == 'status_code' and 'value' in sig:
                        if http_data.get('status_code') == sig['value']:
                            match = True
                            self.matched_signature = f"Status code: {sig['value']}"

                # If any signature matched, return True
                if match:
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking WAF block: {e}", exc_info=True)
            return False

    def _extract_http_data(self, packet):
        """Extract HTTP data from a packet"""
        if Raw not in packet:
            return None

        try:
            # Get raw payload
            payload = bytes(packet[Raw])

            # Check if this looks like HTTP data
            if not (payload.startswith(b'HTTP/') or  # Response
                    any(verb in payload[:20] for verb in  # Request
                        [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS '])):
                return None

            # Try to decode as text
            try:
                text = payload.decode('utf-8', errors='replace')
            except:
                text = None

            # Parse HTTP response
            if payload.startswith(b'HTTP/'):
                # This is a response

                # Extract status code
                status_code = None
                status_line = payload.split(b'\r\n', 1)[0].decode('utf-8', errors='replace')
                if ' ' in status_line:
                    try:
                        status_code = int(status_line.split(' ')[1])
                    except (ValueError, IndexError):
                        pass

                # Split headers and body
                if b'\r\n\r\n' in payload:
                    headers_part, body = payload.split(b'\r\n\r\n', 1)
                else:
                    headers_part, body = payload, b''

                # Parse headers
                headers = {}
                header_lines = headers_part.split(b'\r\n')[1:]  # Skip status line
                for line in header_lines:
                    if b':' in line:
                        name, value = line.split(b':', 1)
                        headers[name.decode('utf-8', errors='replace').strip()] = \
                            value.decode('utf-8', errors='replace').strip()

                return {
                    'type': 'response',
                    'status_code': status_code,
                    'headers': headers,
                    'body': body,
                    'raw': payload
                }

            else:
                # This is a request

                # Split into request line, headers, body
                parts = payload.split(b'\r\n\r\n', 1)
                header_part = parts[0]
                body = parts[1] if len(parts) > 1 else b''

                # Get request line
                lines = header_part.split(b'\r\n')
                request_line = lines[0].decode('utf-8', errors='replace')

                # Parse headers
                headers = {}
                for line in lines[1:]:
                    if b':' in line:
                        name, value = line.split(b':', 1)
                        headers[name.decode('utf-8', errors='replace').strip()] = \
                            value.decode('utf-8', errors='replace').strip()

                return {
                    'type': 'request',
                    'request_line': request_line,
                    'headers': headers,
                    'body': body,
                    'raw': payload
                }

        except Exception as e:
            logger.error(f"Error extracting HTTP data: {e}")
            return None