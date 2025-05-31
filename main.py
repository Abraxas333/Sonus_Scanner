# main.py - Main execution script
import multiprocessing
import asyncio
import os
import sys
import logging
import domain_getter
from functools import partial
from scanner import AsyncScanner  # Your scanner implementation

# Logging
logging.basicConfig(
    filename="log.txt",
    filemode="w",
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s: %(message)s"
)

# Redirect uncaught exceptions into the log
def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        # Let Ctrl-C behave normally
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logging.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

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
# Global list, loaded once at startup
VPN_CONFIGS = []  # Will be populated with available .ovpn files

def load_vpn_configs():
    global VPN_CONFIGS
    try:
        VPN_CONFIGS = [f for f in os.listdir('/var/www/recon/vpn_configs') if f.endswith('.ovpn')]

    except Exception as e:
        logging.error("Error loading VPN configs: {}".format(e))

output_dir = ''

def process_domain(domain, process_index):
    """
    Function to run in each process - initializes and runs a scanner for one domain
    """

    configure_worker_logging_and_stderr()
    logger = logging.getLogger(__name__)
    # Set up output directory
    #domain_dir = os.path.join(output_base_dir, domain.replace('.', '_').replace('*', 'wildcard')) # not necessary?
    #os.makedirs(domain_dir, exist_ok=True)
    interface = f"tun{process_index}"

    # Create scanner for this domain
    scanner = AsyncScanner(domain, output_dir, interface)

    # Run the async scanner within this process
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Install an asyncio exception handler so unhandled
    # errors in coroutines are sent to the logger instead of stderr:
    def handle_asyncio_exception(loop, context):
        # context is a dict, often containing 'exception' or 'message'
        msg = context.get("exception", context.get("message"))
        logger.error("Asyncio exception: %s", msg, exc_info=context.get("exception"))

    loop.set_exception_handler(handle_asyncio_exception)

    try:
        # Run the full scan workflow for this domain
        result = loop.run_until_complete(scanner.run())
        logging.info(f"Completed scan for {domain}")
        return {"domain": domain, "status": "completed", "result": result}
    except Exception as e:
        logging.error(f"Error scanning {domain}: {str(e)}")
        return {"domain": domain, "status": "error", "error": str(e)}
    finally:
        loop.close()


def main():
    # Get command line arguments
    domains_file = sys.argv[1]
    global output_dir
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "recon_results"
    max_processes = int(sys.argv[3]) if len(sys.argv) > 3 else multiprocessing.cpu_count()

    load_vpn_configs()

    try:
        domains = domain_getter.update_domains(domains_file)
        if not domains:
            logging.info(f"No domains found in {domains_file}")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Error updating {domains_file}: {str(e)}")
        sys.exit(1)

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
                    args=(domain, j)
                )
                batch_tasks.append(task)

            # Wait for batch to complete
            for task in batch_tasks:
                result = task.get()  # This blocks until the task completes
                results.append(result)
                #logging.info(f"Domain {result['domain']} scan finished with status: {result['status']}")

    # Summarize results
    successes = [r for r in results if r['status'] == 'completed']
    errors = [r for r in results if r['status'] == 'error']

    logging.info(f"\nScan Summary:")
    logging.info(f"Total domains: {len(domains)}")
    logging.info(f"Successful scans: {len(successes)}")
    logging.info(f"Failed scans: {len(errors)}")


if __name__ == "__main__":
    logging.info("Starting script")
    main()
    logging.info("Finished script")