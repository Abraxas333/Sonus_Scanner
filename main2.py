import multiprocessing
import asyncio
import os
import sys
import random
import subprocess
import time
import socket
import fcntl
import struct
import logging
import domain_getter
from functools import partial
from scanner import AsyncScanner

###### LOGGING ######

# Logging - Configure at the very beginning
logging.basicConfig(
    filename="log.txt",
    filemode="w",
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s: %(message)s"
)

# Create a logger for this module
logger = logging.getLogger(__name__)


# Redirect uncaught exceptions into the log
def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        # Let Ctrl-C behave normally
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))


sys.excepthook = handle_exception


def configure_worker_logging_and_stderr():
    import sys, logging

    # If this child process has no handlers yet, attach one.
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            filename="log.txt",
            filemode="a",
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)s: %(message)s"
        )

    # Redirect any writes to stderr into the logger
    class WorkerStderrToLogger:
        def write(self, message):
            message = message.rstrip()
            if message:
                logging.error(message)

        def flush(self):
            pass

    sys.stderr = WorkerStderrToLogger()

    # Reinstall excepthook so that uncaught exceptions in this WORKER go into log.txt
    def worker_excepthook(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        logging.error("Uncaught exception (worker)",
                      exc_info=(exc_type, exc_value, exc_traceback))

    sys.excepthook = worker_excepthook

###### OS INTERFACE & ROUTING SETUP ######

def cleanup_iptables(max_processes):
    """Clean up any leftover iptables rules"""
    for i in range(max_processes):
        subprocess.run([
            'sudo', 'ip', 'netns', 'exec', f'ns{i}',
            'iptables', '-t', 'raw', '-F'
        ], capture_output=True)

# create/verify network namespaces
def ensure_namespace(idx):
    ns = f"ns{idx}"
    out = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    if ns not in out.stdout.split():
        subprocess.run(["sudo", "ip", "netns", "add", ns], check=True)
        subprocess.run(["sudo", "mkdir", "-p", f"/etc/netns/{ns}"], check=True)
        subprocess.run(["sudo", "cp", "/etc/resolv.conf", f"/etc/netns/{ns}/resolv.conf"], check=True)

        # Create a TUN interface inside that namespace:
        iface = f"tun{idx}"
        subprocess.run([
            "sudo", "ip", "netns", "exec", ns,
            "ip", "tuntap", "add", "dev", iface, "mode", "tun"
        ], check=True)
        subprocess.run([
            "sudo", "ip", "netns", "exec", ns,
            "ip", "link", "set", iface, "up"
        ], check=True)


def link_namespace(i):
    host_if = f"veth{i}-host"
    ns_if   = f"veth{i}-ns"
    ns      = f"ns{i}"
    subnet  = f"10.200.{i}.0/24"
    host_ip = f"10.200.{i}.1/24"
    ns_ip   = f"10.200.{i}.2/24"

    # 1) Create the veth pair on the host (if it doesn’t already exist)
    existing = subprocess.run(
        ["ip", "link", "show"],
        capture_output=True, text=True
    ).stdout

    if host_if not in existing:
        subprocess.run(
            ["sudo", "ip", "link", "add", host_if, "type", "veth", "peer", "name", ns_if],
            check=True
        )

    # 2) Move the “ns\_if” end into namespace “ns{i}”
    subprocess.run(
        ["sudo", "ip", "link", "set", ns_if, "netns", ns],
        check=True
    )

    # 3) Configure host side
    subprocess.run(
        ["sudo", "ip", "addr", "add", host_ip, "dev", host_if],
        check=True
    )
    subprocess.run(
        ["sudo", "ip", "link", "set", host_if, "up"],
        check=True
    )

    # 4) Configure namespace side
    subprocess.run(
        ["sudo", "ip", "netns", "exec", ns, "ip", "addr", "add", ns_ip, "dev", ns_if],
        check=True
    )
    subprocess.run(
        ["sudo", "ip", "netns", "exec", ns, "ip", "link", "set", ns_if, "up"],
        check=True
    )
    subprocess.run(
        ["sudo", "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"],
        check=True
    )

    # Add a default route inside the namespace via the host end
    subprocess.run(
        ["sudo", "ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", "10.200.%d.1" % i],
        check=True
    )

    # 5) On the host, NAT that entire /24 out via your real interface (e.g. eth0)
    subprocess.run(
        ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", "eth0", "-j", "MASQUERADE"],
        check=True
    )


def setup_all_namespaces(count):
    for i in range(count):
        ensure_namespace(i)
        link_namespace(i)   # <— give “ns{i}” a veth uplink to the host

###### LOADING OVPN CONFIGURATION FILES ######

# Global list of ovpn configuration files, loaded once at startup
VPN_CONFIGS = []  # Will be populated with available .ovpn files

def load_vpn_configs():
    global VPN_CONFIGS
    try:
        VPN_CONFIGS = [f for f in os.listdir('/var/www/recon/vpn_configs') if f.endswith('.ovpn')]

        logger.info(f"Loaded {len(VPN_CONFIGS)} VPN configurations")
    except Exception as e:
        logger.error(f"Error loading VPN configs: {str(e)}", exc_info=True)




###### SCANNER SETUP AND DOMAIN ALLOCATION ######

output_dir = ''
def process_domain(domain, process_index):
    configure_worker_logging_and_stderr()

    interface = f"tun{process_index}"
    namespace = f"ns{process_index}"


    # 2) Build the command: run scanner_worker.py inside the namespace
    #
    #    ip netns exec <namespace> python3 scanner_worker.py <domain> <output_dir> <interface> <namespace>
    #
    cmd = [
        "sudo", "ip", "netns", "exec", namespace,
        sys.executable,                       # e.g. /usr/bin/python3
        os.path.join(os.path.dirname(__file__), "scanner_worker.py"),
        domain,
        output_dir,
        interface,
        namespace
    ]

    try:
        logging.info(f"Launching worker for {domain} in namespace {namespace} on {interface}")
        # Run it synchronously; you can capture STDOUT/STDERR if needed
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            logging.error(f"scanner_worker.py failed for {domain}: {proc.stderr.strip()}")
            return {"domain": domain, "status": "error", "error": proc.stderr.strip()}
        else:
            logging.info(f"Scanner worker for {domain} completed successfully")
            # If you want to parse a JSON output from scanner_worker, capture proc.stdout here
            return {"domain": domain, "status": "completed", "output": proc.stdout}
    except Exception as e:
        logging.error(f"Exception launching scanner_worker: {e}", exc_info=True)
        return {"domain": domain, "status": "error", "error": str(e)}


def is_vpn_active_in_namespace(interface, namespace):
    """Check if VPN is already active on interface within the namespace"""
    try:
        # Run ip addr show in the namespace
        result = subprocess.run(
            ['sudo', 'ip', 'netns', 'exec', namespace, 'ip', 'addr', 'show', interface],
            capture_output=True,
            text=True
        )

        if result.returncode == 0 and 'inet ' in result.stdout:
            # Interface exists and has IP
            return True
        return False
    except Exception as e:
        logger.error(f"Error checking VPN in namespace: {e}")
        return False

def main():
    logger.info("Starting main script")

    # Get command line arguments
    if len(sys.argv) < 2:
        logger.error("Usage: python main.py <domains_file> [output_dir] [max_processes]")
        sys.exit(1)

    domains_file = sys.argv[1]
    global output_dir
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "recon_results"
    max_processes = int(sys.argv[3]) if len(sys.argv) > 3 else multiprocessing.cpu_count()

    logger.info(f"Domains file: {domains_file}")
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Max processes: {max_processes}")

    cleanup_iptables(max_processes)

    load_vpn_configs()

    setup_all_namespaces(max_processes)
    try:
        domains = domain_getter.update_domains(domains_file)
        if not domains:
            logger.warning(f"No domains found in {domains_file}")
            sys.exit(1)
        logger.info(f"Loaded {len(domains)} domains")
    except Exception as e:
        logger.error(f"Error updating {domains_file}: {str(e)}", exc_info=True)
        sys.exit(1)

    # Create output directory
    try:
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Created output directory: {output_dir}")
    except Exception as e:
        logger.error(f"Error creating output directory: {str(e)}", exc_info=True)
        sys.exit(1)

    with multiprocessing.Pool(processes=max_processes) as pool:
        results = []

        # Process domains in batches
        for i, domain_batch in enumerate([domains[i:i + max_processes] for i in range(0, len(domains), max_processes)]):
            logger.info(f"Processing batch {i + 1} with {len(domain_batch)} domains")
            batch_tasks = []

            for j, domain in enumerate(domain_batch):
                # j is the process index within this batch (0-7)
                task = pool.apply_async(
                    process_domain,
                    args=(domain, j)
                )
                batch_tasks.append(task)

            # Wait for batch to complete
            for task in batch_tasks:
                try:
                    result = task.get(timeout=300)  # 5 minute timeout per domain
                    results.append(result)
                    logger.info(f"Domain {result['domain']} scan finished with status: {result['status']}")
                except multiprocessing.TimeoutError:
                    logger.error(f"Timeout processing domain")
                    results.append({"domain": "unknown", "status": "timeout"})
                except Exception as e:
                    logger.error(f"Error getting task result: {str(e)}", exc_info=True)
                    results.append({"domain": "unknown", "status": "error", "error": str(e)})

    # Summarize results
    successes = [r for r in results if r['status'] == 'completed']
    errors = [r for r in results if r['status'] == 'error']
    timeouts = [r for r in results if r['status'] == 'timeout']

    logger.info("\nScan Summary:")
    logger.info(f"Total domains: {len(domains)}")
    logger.info(f"Successful scans: {len(successes)}")
    logger.info(f"Failed scans: {len(errors)}")
    logger.info(f"Timed out scans: {len(timeouts)}")

    if errors:
        logger.info("\nFailed domains:")
        for err in errors[:10]:  # Show first 10 errors
            logger.error(f"  {err['domain']}: {err.get('error', 'Unknown error')}")

if __name__ == "__main__":
    try:
        logger.info("=" * 60)
        logger.info("Starting domain scanner")
        logger.info("=" * 60)
        main()
        logger.info("=" * 60)
        logger.info("Script completed successfully")
        logger.info("=" * 60)
    except Exception as e:
        logger.error("Fatal error in main", exc_info=True)
        sys.exit(1)