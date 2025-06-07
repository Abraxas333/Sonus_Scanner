import sys, asyncio, logging
from scanner import AsyncScanner

logging.basicConfig(
    filename="log.txt", filemode="a", level=logging.DEBUG,
    format="%(asctime)s %(levelname)s: %(message)s"
)

def main():
    if len(sys.argv) != 5:
        print("Usage: scanner_worker.py <target> <output_dir> <interface> <namespace>")
        sys.exit(1)
    target     = sys.argv[1]
    output_dir = sys.argv[2]
    iface      = sys.argv[3]
    namespace  = sys.argv[4]

    logger = logging.getLogger(__name__)
    logger.info(f"Worker starting: {target} on iface {iface} in ns {namespace}")

    sc = AsyncScanner(
        target=target,
        output_dir=output_dir,
        interface=iface,
        namespace=namespace
        # (no vpn_conf here, because AsyncScanner can pick one)
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    def handle_exc(loop, ctx):
        msg = ctx.get("message") or ctx.get("exception")
        logging.error(f"Asyncio exception: {msg}", exc_info=ctx.get("exception"))
    loop.set_exception_handler(handle_exc)

    try:
        # First bring up the VPN from inside the namespace:
        loop.run_until_complete(sc.start_vpn_connection())
        # Then run the actual scan (DNS → pcap → waf sniff)
        loop.run_until_complete(sc.run())
    except Exception as e:
        logger.error(f"Fatal in worker for {target}: {e}", exc_info=True)
    finally:
        loop.close()

if __name__ == "__main__":
    main()
