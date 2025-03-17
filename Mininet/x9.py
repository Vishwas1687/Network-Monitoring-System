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

# Global dictionary for IP mapping
ip_map_global = {}

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

# Generate a mapping of public IPs to private IPs
def generate_ip_mapping(public_ips):
    """Map public IP addresses to private 10.0.0.x addresses."""
    return {public_ip: f'10.0.0.{i+1}' for i, public_ip in enumerate(public_ips)}

# Random topology with hosts and switches
class RandomTopo(Topo):
    """Random topology with 10 switches and dynamically assigned hosts."""
    def build(self, host_count=5):  # Default value provided
        switches = [self.addSwitch(f's{i+1}', cls=OVSKernelSwitch) for i in range(10)]
        hosts = []
        
        for i in range(1, host_count + 1):
            host = self.addHost(f'h{i}', ip=f'10.0.0.{i}', mac=f'00:00:00:00:00:{i:02x}')
            chosen_switch = random.choice(switches)
            self.addLink(host, chosen_switch)
            hosts.append(host)
        
        for _ in range(15):  # Random switch interconnections
            s1, s2 = random.sample(switches, 2)
            self.addLink(s1, s2)

# Find the corresponding Mininet host for a private IP
def get_host_from_ip(net, private_ip):
    """Find corresponding Mininet host for a given private IP."""
    for host in net.hosts:
        if host.IP() == private_ip:
            return host
    return None

# Replay packets using mapped private IPs
def replay_packets(net, pcap_file):
    """Replay packets dynamically based on source IP mapping using Scapy."""
    global ip_map_global
    packets = scapy.rdpcap(pcap_file)
    packets_by_src = {}

    # Group packets by original public IP
    for packet in packets:
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            if src_ip in ip_map_global:
                if src_ip not in packets_by_src:
                    packets_by_src[src_ip] = []
                packets_by_src[src_ip].append(packet)

    # Process each source IP
    for src_ip, ip_packets in packets_by_src.items():
        private_ip = ip_map_global.get(src_ip)
        host = get_host_from_ip(net, private_ip)
        
        if not host:
            info(f"No host found for IP {private_ip} (mapped from {src_ip}). Skipping.\n")
            continue
            
        info(f"Replaying {len(ip_packets)} packets from {src_ip} (mapped to {private_ip}) on {host.name}...\n")
        
        # Create a temporary file for modified packets
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp_pcap:
            temp_pcap_path = temp_pcap.name
            # Don't modify packets here, we'll do it in the script
            scapy.wrpcap(temp_pcap_path, ip_packets)
        
        # Create Python script to send packets with remapped IPs
        script = """
import scapy.all as scapy
import time

def send_packet(packet, iface):
    try:
        # Ensure Ethernet layer
        if scapy.Ether not in packet:
            packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / packet
            
        # Remap IP addresses
        if scapy.IP in packet:
            # Get original addresses
            original_src = packet[scapy.IP].src
            original_dst = packet[scapy.IP].dst
            
            # Map IPs
            ip_map = {0}
            
            # Update source and destination IPs
            packet[scapy.IP].src = ip_map.get(original_src, original_src)
            packet[scapy.IP].dst = ip_map.get(original_dst, original_dst)
            
            # Delete checksum to force recalculation
            del packet[scapy.IP].chksum
            
            # If TCP/UDP present, delete their checksums too
            if scapy.TCP in packet:
                del packet[scapy.TCP].chksum
            if scapy.UDP in packet:
                del packet[scapy.UDP].chksum
        
        # Send the packet
        scapy.sendp(packet, iface=iface, verbose=0)
        return True
    except Exception as e:
        print(f"Error sending packet: {{e}}")
        return False

# Load packets
packets = scapy.rdpcap("{1}")
print(f"Loaded {{len(packets)}} packets from PCAP")

# Send each packet
success = 0
failed = 0
for i, packet in enumerate(packets):
    if send_packet(packet, "{2}-eth0"):
        success += 1
    else:
        failed += 1
    time.sleep(0.01)  # Small delay between packets

print(f"Sent {{success}} packets successfully, {{failed}} failed")
"""
        
        # Format the script with proper values
        script_content = script.format(
            repr(ip_map_global),  # Pass the IP mapping dictionary
            temp_pcap_path,       # PCAP file path
            host.name             # Host name
        )
        
        # Write the script to a temporary file
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as script_file:
            script_path = script_file.name
            script_file.write(script_content.encode())
        
        # Execute the script
        result = host.cmd(f"python3 {script_path}")
        info(f"Result for {host.name}: {result}\n")
        
        # Clean up
        os.remove(script_path)
        os.remove(temp_pcap_path)
        
        # Small delay before next host
        time.sleep(0.5)

# Run the Mininet topology and replay packets
def run_topology(pcap_file):
    """Run the Mininet topology and replay packets."""
    global ip_map_global
    setLogLevel('info')

    # Extract public IPs and create mapping
    public_ips = extract_public_ips(pcap_file)
    if not public_ips:
        info("No valid public IPs found in the PCAP file.\n")
        return

    # Generate and store IP mapping
    ip_map_global = generate_ip_mapping(public_ips)
    
    # Count hosts needed based on mapping
    host_count = len(ip_map_global)
    info(f"Creating topology with {host_count} hosts for {len(public_ips)} public IPs\n")
    
    # Create topology with correct host count
    topo = RandomTopo(host_count=host_count)
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), link=TCLink)
    net.start()

    # Show IP mapping
    info(f"Mapped {len(ip_map_global)} public IPs to private subnet:\n")
    for public_ip, private_ip in ip_map_global.items():
        info(f"  {public_ip} -> {private_ip}\n")
    
    # Test network connectivity
    info("Testing network connectivity...\n")
    net.pingAll()
    
    # Replay packets
    replay_packets(net, pcap_file)

    # Dump OVS port info for all switches
    for i in range(1, 11):
        info(f"\nChecking OVS Flow Table for s{i}:\n")
        os.system(f"sudo ovs-ofctl dump-ports s{i}")

    # Start CLI
    CLI(net)
    net.stop()

if __name__ == "__main__":
    pcap_file = "traffic_1.pcap"  # Replace with your PCAP file
    run_topology(pcap_file)