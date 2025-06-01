# main.py - Main execution script with fixed logging
import multiprocessing
import asyncio
import os
import sys
import logging
import domain_getter
from functools import partial
from scanner import AsyncScanner  # Your scanner implementation

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


# Global list, loaded once at startup
VPN_CONFIGS = []  # Will be populated with available .ovpn files


def load_vpn_configs():
    global VPN_CONFIGS
    try:
        VPN_CONFIGS = [f for f in os.listdir('/var/www/recon/vpn_configs') if f.endswith('.ovpn')]
        logger.info(f"Loaded {len(VPN_CONFIGS)} VPN configurations")
    except Exception as e:
        logger.error(f"Error loading VPN configs: {str(e)}", exc_info=True)


output_dir = ''


def process_domain(domain, process_index):
    """
    Function to run in each process - initializes and runs a scanner for one domain
    """
    configure_worker_logging_and_stderr()
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"Starting scan for domain: {domain} with process index: {process_index}")

        # Set up output directory
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
            logger.error(f"Asyncio exception: {msg}", exc_info=context.get("exception"))

        loop.set_exception_handler(handle_asyncio_exception)

        try:
            # Run the full scan workflow for this domain
            result = loop.run_until_complete(scanner.run())
            logger.info(f"Completed scan for {domain}")
            return {"domain": domain, "status": "completed", "result": result}
        except Exception as e:
            logger.error(f"Error scanning {domain}: {str(e)}", exc_info=True)
            return {"domain": domain, "status": "error", "error": str(e)}
        finally:
            loop.close()

    except Exception as e:
        logger.error(f"Process-level error for {domain}: {str(e)}", exc_info=True)
        return {"domain": domain, "status": "error", "error": str(e)}


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

    load_vpn_configs()

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