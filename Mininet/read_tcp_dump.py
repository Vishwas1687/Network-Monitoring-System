import subprocess
import time
import os
import scapy.all as scapy
import signal
from mininet.log import setLogLevel, info
from prometheus_client import start_http_server, Counter

PCAP_FILE_1 = "mininet_traffic_1.pcap"
PCAP_FILE_2 = "mininet_traffic_2.pcap"
ACTIVE_FILE = PCAP_FILE_1

tcp_syn_count = Counter('tcp_syn_packets', 'Number of TCP SYN packets processed')

def start_tcpdump(filename):
    """Starts a tcpdump process to capture Mininet traffic."""
    return subprocess.Popen(
        ["sudo", "tcpdump", "-i", "any", "net", "10.0.0.0/8", "-w", filename],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def stop_tcpdump(process):
    """Stops the tcpdump process gracefully, with a timeout."""
    if process:
        process.terminate()  # Graceful stop
        try:
            process.wait(timeout=3)  # Wait up to 3 seconds
        except subprocess.TimeoutExpired:
            print("Forcing tcpdump to stop...")
            process.kill()  # Force stop if it doesn't exit
            process.wait()

def read_pcap(filename):
    """Reads and processes packets from a pcap file."""
    try:
        packets = scapy.rdpcap(filename)
        print(f"Read {len(packets)} packets from {filename}")
        
        # Example processing: Count TCP SYN packets
        syn_count = sum(1 for pkt in packets if scapy.TCP in pkt and pkt[scapy.TCP].flags & 0x02)
        tcp_syn_count.inc(syn_count)

    except Exception as e:
        print(f"Error reading {filename}: {e}")

    # Delete the file after reading
    os.remove(filename)
    print(f"Deleted {filename}")

def main():
    global ACTIVE_FILE
    setLogLevel('info')
    print("Starting the packet capture rotation...") 
    info("\nMetrics Exporter running on port 8082.\n")
    start_http_server(8082)

    # Start capturing to the first file
    tcpdump_proc = start_tcpdump(ACTIVE_FILE)
    time.sleep(15)  # Let it run for 15 seconds

    while True:
        # Switch files
        new_file = PCAP_FILE_2 if ACTIVE_FILE == PCAP_FILE_1 else PCAP_FILE_1

        # Stop current capture
        stop_tcpdump(tcpdump_proc)

        # Short delay before starting new capture
        time.sleep(1)

        # Start new capture
        tcpdump_proc = start_tcpdump(new_file)

        # Process the old file
        read_pcap(ACTIVE_FILE)

        # Update active file
        ACTIVE_FILE = new_file

        # Sleep for 15 seconds before switching again
        time.sleep(15)

if __name__ == "__main__":
    main()
