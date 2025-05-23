# main.py - Main execution script
import multiprocessing
import asyncio
import os
import sys
from functools import partial

from scanner import AsyncScanner  # Your scanner implementation
from vpn_manager import VPNManager  # VPN management class

# Global list, loaded once at startup
VPN_CONFIGS = []  # Will be populated with available .ovpn files

def load_vpn_configs():
    global VPN_CONFIGS
    try:
        VPN_CONFIGS = [f for f in os.listdir('/etc/openvpn/client') if f.endswith('.ovpn')]

    except Exception as e:
        print("Error loading VPN configs: {}".format(e))


async def process_domain(domain, output_base_dir, vpn_config_dir, process_index):
    """
    Function to run in each process - initializes and runs a scanner for one domain
    """
    # Set up output directory
    domain_dir = os.path.join(output_base_dir, domain.replace('.', '_').replace('*', 'wildcard')) # not necessary?
    os.makedirs(domain_dir, exist_ok=True)
    interface = f"tun{process_index}"

    # Create scanner for this domain
    scanner = AsyncScanner(domain, domain_dir, interface)
    
    scanner.start_vpn_connection()
    # Run the async scanner within this process
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        # Run the full scan workflow for this domain
        result = loop.run_until_complete(scanner.run_full_scan())
        print(f"Completed scan for {domain}")
        return {"domain": domain, "status": "completed", "result": result}
    except Exception as e:
        print(f"Error scanning {domain}: {str(e)}")
        return {"domain": domain, "status": "error", "error": str(e)}
    finally:
        loop.close()


def main():
    # Get command line arguments
    domains_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "recon_results"
    max_processes = int(sys.argv[3]) if len(sys.argv) > 3 else multiprocessing.cpu_count()

    load_vpn_configs()

    # Read domains from file
    with open(domains_file, 'r') as file:
        domains = [line.strip() for line in file.readlines()]

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    with multiprocessing.Pool(processes=max_processes) as pool:
        results = []
        for i, domain_batch in enumerate([domains[i:i + max_processes] for i in range(0, len(domains), max_processes)]):
            batch_tasks = []
            for j, domain in enumerate(domain_batch):
                # j is the process index within this batch (0-7)
                task = pool.apply_async(
                    process_domain,
                    args=(domain, output_dir, j)
                )
                batch_tasks.append(task)

            # Wait for batch to complete
            for task in batch_tasks:
                result = task.get()  # This blocks until the task completes
                results.append(result)
                print(f"Domain {result['domain']} scan finished with status: {result['status']}")

    # Summarize results
    successes = [r for r in results if r['status'] == 'completed']
    errors = [r for r in results if r['status'] == 'error']

    print(f"\nScan Summary:")
    print(f"Total domains: {len(domains)}")
    print(f"Successful scans: {len(successes)}")
    print(f"Failed scans: {len(errors)}")


if __name__ == "__main__":
    main()