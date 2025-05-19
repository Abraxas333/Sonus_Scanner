# main.py - Main execution script
import multiprocessing
import asyncio
import os
import sys
from functools import partial

from scanner import AsyncScanner  # Your scanner implementation
from vpn_manager import VPNManager  # VPN management class


def process_domain(domain, output_base_dir, vpn_interface=None):
    """
    Function to run in each process - initializes and runs a scanner for one domain
    """
    # Set up output directory
    domain_dir = os.path.join(output_base_dir, domain.replace('.', '_').replace('*', 'wildcard'))
    os.makedirs(domain_dir, exist_ok=True)

    # Create scanner for this domain
    scanner = AsyncScanner(domain, domain_dir, vpn_interface)

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


def allocate_vpn_interfaces(vpn_configs, num_processes):
    """
    Initialize VPN interfaces and return interface assignments
    """
    # In a real implementation, this would set up multiple VPN connections
    # For now, we'll just return interface names
    vpn_manager = VPNManager()
    loop = asyncio.get_event_loop()
    interfaces = loop.run_until_complete(vpn_manager.start_multiple_vpns(vpn_configs))

    # Create a mapping of process index to interface
    interface_assignments = {}
    for i in range(num_processes):
        # Assign interfaces in a round-robin fashion
        if interfaces:
            interface_assignments[i] = interfaces[i % len(interfaces)]
        else:
            interface_assignments[i] = None

    return interface_assignments


def main():
    # Get command line arguments
    domains_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "recon_results"
    max_processes = int(sys.argv[3]) if len(sys.argv) > 3 else multiprocessing.cpu_count()

    # Read domains from file
    with open(domains_file, 'r') as file:
        domains = [line.strip() for line in file.readlines()]

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Set up VPN interfaces if needed
    vpn_configs = [f for f in os.listdir('/etc/openvpn/client') if f.endswith('.ovpn')]
    interface_assignments = allocate_vpn_interfaces(vpn_configs, max_processes)

    # Create a pool with the determined max processes
    with multiprocessing.Pool(processes=max_processes) as pool:
        # Process domains in batches to control concurrency
        results = []
        for i, domain_batch in enumerate([domains[i:i + max_processes] for i in range(0, len(domains), max_processes)]):
            batch_tasks = []
            for j, domain in enumerate(domain_batch):
                process_idx = i * max_processes + j
                vpn_interface = interface_assignments.get(process_idx % max_processes)

                # Create task for this domain
                task = pool.apply_async(
                    process_domain,
                    args=(domain, output_dir, vpn_interface)
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