# packet_interceptor.py
import sys
import time
import json
import logging
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
from waf_signatures import get_signatures

logger = logging.getLogger(__name__)


def packet_handler(target_ip, output_dir, queue_num):
    """Intercept and process packets for a specific target"""
    waf_signatures = get_signatures()
    packets_log = []

    def process_packet(packet):
        try:
            # Get packet data
            pkt_data = packet.get_payload()
            pkt = IP(pkt_data)

            # Only process packets to/from our target
            if pkt.dst != target_ip and pkt.src != target_ip:
                packet.accept()
                return

            # Log packet info
            packet_info = {
                "src": pkt.src,
                "dst": pkt.dst,
                "proto": pkt.proto,
                "timestamp": time.time()
            }

            # Analyze TCP packets
            if TCP in pkt:
                packet_info["sport"] = pkt[TCP].sport
                packet_info["dport"] = pkt[TCP].dport
                packet_info["flags"] = pkt[TCP].flags

                # Check for WAF blocks
                if pkt[TCP].flags & 0x04:  # RST flag
                    packet_info["waf_block"] = "TCP RST"

                # Extract HTTP data if present
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
                    if b'HTTP' in payload[:10]:
                        packet_info["http_snippet"] = payload[:100].decode('utf-8', errors='ignore')

            packets_log.append(packet_info)

            # Write to log file periodically
            if len(packets_log) >= 50:
                flush_logs(output_dir, packets_log)
                packets_log.clear()

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

        # Always accept the packet to avoid blocking traffic
        packet.accept()

    def flush_logs(output_dir, logs):
        """Write packet logs to file"""
        log_file = f"{output_dir}/packet_intercept.jsonl"
        try:
            with open(log_file, "a") as f:
                for log_entry in logs:
                    f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            logger.error(f"Error writing logs: {e}")

    # Create NFQUEUE handler
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, process_packet)

    try:
        logger.info(f"Starting packet interception for {target_ip} on queue {queue_num}")
        nfqueue.run()
    except KeyboardInterrupt:
        logger.info("Packet interception stopped by user")
    except Exception as e:
        logger.error(f"Error in packet handler: {e}")
    finally:
        # Flush remaining logs
        if packets_log:
            flush_logs(output_dir, packets_log)

        nfqueue.unbind()

        # Clean up iptables rules
        import subprocess
        try:
            subprocess.run(['iptables', '-t', 'raw', '-D', 'OUTPUT',
                            '-d', target_ip, '-j', 'NFQUEUE', '--queue-num', str(queue_num)],
                           capture_output=True)
        except:
            pass


if __name__ == "__main__":
    # Allow running directly for testing
    if len(sys.argv) != 4:
        print("Usage: packet_interceptor.py <target_ip> <output_dir> <queue_num>")
        sys.exit(1)

    target_ip = sys.argv[1]
    output_dir = sys.argv[2]
    queue_num = int(sys.argv[3])

    packet_handler(target_ip, output_dir, queue_num)