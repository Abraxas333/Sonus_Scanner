import scapy as scapy
import subprocess as sp
import os
import sys
import json
import multiprocessing as mp 
from functools import partial
import asyncio
from datetime import datetime

from scapy.layers.inet import IP, TCP
from scapy.modules.nmap import nmap_match_one_sig

sp.run('')

RECON_DIR = os.path.abspath(os.path.dirname(__file__)) # Directory where the recon data will be stored, the same as the script directory


class AsyncScanner:
    def __init__(self, target, output_dir, interface):
        self.target = target
        self.output_dir = output_dir
        self.interface = interface
        self.results = []
        self.blocked = False
        self.active_scans = {}
        
    # check if domain is a wildcard (*.example.com) or standard (example.com)
    async def check_domain_type(self):
        if '*' in self.target:
            return 'wildcard'
        else:
            return 'standard'

    # helper methods
    def _register_tool(self, tool):
        task_id = id(asyncio.current_task())
        self.active_scans[task_id] = tool
        return task_id

    def _unregister_tool(self, tool):
        if task_id in self.active_scans:
            del self.active_scans[task_id]

    def get_active_tools(self):
        return list(self.active_scans.values())

    # create parent directory where subsequent scans can create dirs for their results
    # format: wildcard.example.com or example.com
    # set self.output_dir = directory name and return it
    async def create_domain_dir(self):
        # Create a directory for the domain if it doesn't exist
        # assign self.output dir the domain directory
        domain_type = await self.check_domain_type()
        if domain_type == 'wildcard':
            domain_dir = os.path.join(self.output_dir, self.target.replace('*', 'wildcard'))
            os.makedirs(domain_dir, exist_ok=True)
            self.output_dir = domain_dir
        else:
            return 0

        return self.output_dir

    # run amass on wildcard domains and create directories for each found subdomain
    async def enumerate_subdomains(self):
        domain_type = await self.create_domain_dir()
        if domain_type != 'wildcard':
            return

        # strip the asterisk from the target and format the target into a wildcard domain dir name
        stripped_domain = self.target.replace('*', '')
        # start amass subdomain enumeration
        task_id = self._register_tool('amass')

        cmd = [self.current_scan_tool, 'enum', '-d', stripped_domain, '-o', os.path.join(self.output_dir, self.target.replace('*', 'wildcard'))]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode == 0:
                subdomains_found = [line.strip() for line in stdout.decode().split('\n')
                                    if line.strip() # throw away lines that are emtpy after stipping
                                    ]
                if subdomains_found:
                    directory_tasks = []
                    for subdomain in subdomains_found:
                        subdomain_dir = os.path.join(self.output_dir, subdomain)
                        task = asyncio.create_task(
                            self._create_subdomain_directory(subdomain, subdomain_dir)
                        )
                        directory_tasks.append(task)

                    await asyncio.gather(*directory_tasks)
                    print(f"Created directories for {len(subdomains_found)} subdomains")
                else:
                    print(f"No subdomains found for {stripped_domain}")
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                print(f"Amass failed: {error_msg}")
                self.results.append({
                    'tool': self.current_scan_tool,
                    'status': 'failed',
                    'message': error_msg,
                    'domain': stripped_domain,
                })
        except Exception as e:
            print(f"Error during subdomain enumeration: {e}")
            self.results.append({
                'tool': self.current_scan_tool,
                'status': 'failed',
                'error': str(e)
            })

        finally:
            self._unregister_tool(task_id)

        return [
            {
                'subdomain': result['subdomain'],
                'directory': result['directory']
            }
            for result in self.results
            if 'subdomain' in result and result['status'] == 'created'
        ]



    async def _create_subdomain_directory(self, subdomain, directory):
        os.makedirs(directory, exist_ok=True)
        self.results.append({
            'subdomain': subdomain,
            'directory': directory,
            'status': 'created'
        })
        return {
            'subdomain': subdomain,
            'directory': directory
        }

    async def check_liveness(self):
        # Set tool
        task_id = self._register_tool('dig')

        try:
            # Use dig with +short to get just the IP addresses
            cmd = ['dig', self.target, 'A', '+short']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # Get IP addresses from output
            output = stdout.decode().strip()

            # If there's no output, domain is not live
            if not output:
                print(f"Domain {self.target} is not live (no A records)")
                return False

            # Domain is live - create directory if needed
            domain_dir = self.output_dir
            os.makedirs(domain_dir, exist_ok=True)

            # Parse IP addresses
            ip_addresses = [ip.strip() for ip in output.split('\n') if ip.strip()]

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

            print(f"Domain {self.target} is live with {len(ip_addresses)} IP addresses")
            return True

        except Exception as e:
            print(f"Error checking liveness for {self.target}: {str(e)}")
            return False

        finally:
            self._unregister_tool(task_id)

    async def sniff_waf(self, custom_headers=False, headers_file=None, ):
        task_id = self._register_tool("wafw00f")
        result_file = os.path.join(self.output_dir, "waf.json")
        log_file = os.path.join(self.output_dir, "waf_log.json")

        try:
            cmd = ['/usr/bin/wafw00f', 'http://' + self.target, '-a', '-f', 'json', '-o', result_file, '-vvv' + f" 2>&1 | tee {log_file}"]

            if custom_headers and headers_file:
                if os.path.exists(headers_file):
                    cmd.extend(['-H', headers_file])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PYTHONUNBUFFERED":    "1"}
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
                    with open(result_file, 'r') as f:
                        waf_data = json.load(f)

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

                # Extract specific details for easier access
                reasons = [line for line in parsed_log["detection_results"] if "Reason:" in line]
                if reasons:
                    result["blocking_reason"] = reasons[0].split("Reason:", 1)[1].strip()

                # Save the structured log
                with open(log_file, 'w') as f:
                    json.dump(result, f, indent=2)

                # Store in results dictionary
                self.results["wafw00f"] = result

                print(f"Completed WAF detection for {self.target}")
                if result.get("waf_detected"):
                    print(f"WAF detected: {result.get('firewall', 'Unknown')}")

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
            print(f"Error in WAF detection for {self.target}: {str(e)}")
            return error_result

        finally:
            self._unregister_tool(task_id)


    async def test_waf(self):
        task_id = self._register_tool("vegeta")
        

        pass
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

    async def start_traffic_monitor(self):
        """Start monitoring traffic for WAF blocks"""
        self.stop_monitoring = False

        # Start the monitoring in a separate thread to not block asyncio
        self.monitor_task = asyncio.create_task(self._run_traffic_monitor())
        print(f"Traffic monitoring started for {self.target} on {self.interface}")

    async def stop_traffic_monitor(self):
        """Stop the traffic monitoring"""
        self.stop_monitoring = True
        if hasattr(self, 'monitor_task') and self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        print(f"Traffic monitoring stopped for {self.target}")

    async def _run_traffic_monitor(self):
        """Run the traffic monitoring in a way that doesn't block asyncio"""
        # This runs the monitor in an executor to not block the event loop
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, self._monitor_traffic)
        except Exception as e:
            print(f"Error in traffic monitor: {str(e)}")

    def _monitor_traffic(self):
        """Monitor traffic for WAF blocks using Scapy"""
        # Define WAF block signatures
        waf_signatures = [
            # CloudFlare WAF block indicators
            {"layer": TCP, "field": "dport", "value": 403},
            {"text": b"CloudFlare Ray ID"},
            {"text": b"Access denied"},

            # AWS WAF indicators
            {"text": b"AWS WAF"},

            # Generic WAF indicators
            {"text": b"Request blocked"},
            {"text": b"IP address has been blocked"},
            # Add more signatures as needed
        ]

        # Start capturing packets
        def packet_callback(packet):
            if self.stop_monitoring:
                return

            # Check if the packet is related to our target
            if IP in packet and TCP in packet:
                # Only look at packets to/from our target
                target_ip = self._resolve_target_to_ip()
                if packet[IP].src == target_ip or packet[IP].dst == target_ip:
                    # Check packet against WAF signatures
                    if self._check_waf_block(packet, waf_signatures):
                        print(f"WAF BLOCK DETECTED for {self.target}")
                        self.blocked = True

                        # Log the packet that triggered detection
                        with open(os.path.join(self.output_dir, "waf_block_packet.txt"), "w") as f:
                            f.write(str(packet.show(dump=True)))

                        # Notify for VPN rotation if needed
                        # This would typically trigger an event or callback
                        # For now, we'll just log it
                        print(f"VPN rotation needed for {self.interface}")

        # Start the capture on the specific interface
        try:
            # Filter for TCP traffic to/from our target IP
            target_ip = self._resolve_target_to_ip()
            bpf_filter = f"host {target_ip} and tcp"

            # Use Scapy's sniff function
            scapy.sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=packet_callback,
                store=0,  # Don't store packets in memory
                stop_filter=lambda p: self.stop_monitoring  # Stop when flagged
            )
        except Exception as e:
            print(f"Error in traffic capture: {str(e)}")

    def _check_waf_block(self, packet, signatures):
        """Check if a packet matches any WAF block signatures"""
        # Check layer field values
        for sig in signatures:
            if "layer" in sig and "field" in sig:
                layer = sig["layer"]
                field = sig["field"]
                value = sig["value"]

                if layer in packet and hasattr(packet[layer], field):
                    if getattr(packet[layer], field) == value:
                        return True

        # Check for text patterns in raw packet
        if Raw in packet:
            payload = bytes(packet[Raw])
            for sig in signatures:
                if "text" in sig and sig["text"] in payload:
                    return True

        return False

    def _resolve_target_to_ip(self):
        """Resolve target domain to IP address"""
        # Check if we already have it from liveness check
        if hasattr(self, 'results') and 'dig' in self.results:
            ip = self.results['dig'].get('ip')
            if ip:
                return ip

        # Otherwise resolve it
        try:
            return socket.gethostbyname(self.target)
        except:
            # If resolution fails, return a placeholder
            # This would need better handling in a real implementation
            return "0.0.0.0"