import random
import netaddr
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.node import OVSKernelSwitch, RemoteController
import os
import scapy.all as scapy
import tempfile
import time

# Function to check if an IP is public
def is_public_ip(ip):
    """Check if an IP address is public and not multicast/broadcast/unspecified."""
    ip_obj = netaddr.IPAddress(ip)
    return not (ip_obj.is_private() or ip_obj.is_multicast() or ip_obj.is_reserved() or ip_obj.is_loopback())

# Extract unique public IPs from a PCAP file
def extract_public_ips(pcap_file):
    """Extract unique public IP addresses from a PCAP file."""
    packets = scapy.rdpcap(pcap_file)
    public_ips = set()
    for packet in packets:
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            if is_public_ip(src_ip):
                public_ips.add(src_ip)
    return list(public_ips)

# Random topology with hosts and switches
class RandomTopo(Topo):
    """Random topology with 10 switches and dynamically assigned hosts with actual public IPs."""
    def build(self, ip_list):
        switches = [self.addSwitch(f's{i+1}', cls=OVSKernelSwitch) for i in range(10)]
        hosts = []

        for i, ip in enumerate(ip_list):
            host = self.addHost(f'h{i+1}', ip=ip, mac=f'00:00:00:00:00:{i+1:02x}')
            chosen_switch = random.choice(switches)
            self.addLink(host, chosen_switch)
            hosts.append(host)
        
        for _ in range(15):  # Random switch interconnections
            s1, s2 = random.sample(switches, 2)
            self.addLink(s1, s2)

# Find the corresponding Mininet host for a given IP
def get_host_from_ip(net, src_ip):
    """Find the Mininet host with the given IP."""
    for host in net.hosts:
        if host.IP() == src_ip:
            return host
    return None

# Replay packets without modifying IPs
def replay_packets(net, pcap_file):
    """Replay packets dynamically using Scapy without modifying source IPs."""
    packets = scapy.rdpcap(pcap_file)
    packets_by_src = {}

    # Group packets by original source IP
    for packet in packets:
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            packets_by_src.setdefault(src_ip, []).append(packet)

    # Replay packets for each source IP
    for src_ip, ip_packets in packets_by_src.items():
        host = get_host_from_ip(net, src_ip)
        if not host:
            continue

        info(f"Replaying {len(ip_packets)} packets from {src_ip} on {host.name}...\n")

        # Save packets to a temp file
        temp_pcap = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        scapy.wrpcap(temp_pcap.name, ip_packets)

        # Generate replay script
        script_content = f"""
import os
import scapy.all as scapy

def send_packet(packet, iface):
    try:
        if scapy.Ether not in packet:
            packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / packet
        scapy.sendp(packet, iface=iface, verbose=0)
    except Exception as e:
        print(f'Error in sending packet: {{e}}')

packets = scapy.rdpcap('{temp_pcap.name}')
for pkt in packets:
    send_packet(pkt, '{host.name}-eth0')
"""
        temp_script = tempfile.NamedTemporaryFile(suffix='.py', delete=False)
        temp_script.write(script_content.encode())
        temp_script.close()

        # Run the replay script on the host
        host.cmd(f'python3 {temp_script.name}')

        # Cleanup
        os.remove(temp_script.name)
        os.remove(temp_pcap.name)
        time.sleep(0.5)

# Run the Mininet topology and replay packets
def run_topology(pcap_file):
    """Run the Mininet topology and replay packets."""
    setLogLevel('info')

    public_ips = extract_public_ips(pcap_file)
    if not public_ips:
        info("No valid public IPs found in the PCAP file.\n")
        return

    # Setup Mininet topology
    topo = RandomTopo(public_ips)
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), link=TCLink)
    net.start()

    info(f"Assigned {len(public_ips)} hosts with public IPs:\n{public_ips}\n")
    
    # Replay packets
    replay_packets(net, pcap_file)

    # Dump OVS port info
    os.system("sudo ovs-ofctl dump-ports s1")

    # Start CLI
    CLI(net)
    net.stop()

if __name__ == "__main__":
    pcap_file = "traffic_1.pcap"  # Replace with your PCAP file
    run_topology(pcap_file)
