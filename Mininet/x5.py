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

class CustomTopo(Topo):
    """Custom topology with 3 hosts connected to a switch."""
    def build(self):
        switch = self.addSwitch('s1', cls=OVSKernelSwitch)
        h1 = self.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:01:01')
        h2 = self.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:02:02')
        h3 = self.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:03:03')
        
        self.addLink(h1, switch)
        self.addLink(h2, switch)
        self.addLink(h3, switch)

def setup_ovs_rules():
    """Add OpenFlow rules to forward packets"""
    info("Adding OpenFlow rules to OVS...\n")
    os.system("sudo ovs-ofctl add-flow s1 'priority=1,in_port=1 actions=output:2,3'")
    os.system("sudo ovs-ofctl add-flow s1 'priority=1,in_port=2 actions=output:1,3'")
    os.system("sudo ovs-ofctl add-flow s1 'priority=1,in_port=3 actions=output:1,2'")

def extract_packets(pcap_file):
    """Extracts packets from the pcap file."""
    if not os.path.exists(pcap_file):
        info(f"PCAP file {pcap_file} not found.\n")
        return []
    return scapy.rdpcap(pcap_file)  # Read all packets

def get_host_from_ip(net, ip_map, src_ip):
    """Maps the source IP to the correct Mininet host."""
    for host_name, host_ip in ip_map.items():
        if host_ip == src_ip:
            return net.get(host_name)
    return None

def replay_packets(net, pcap_file, ip_map):
    """Replays packets dynamically based on source IP mapping using Scapy."""
    packets = extract_packets(pcap_file)
    if not packets:
        info("No packets found in the PCAP file.\n")
        return
    
    info(f"Found {len(packets)} packets in the PCAP file.\n")
    
    # Group packets by source IP
    packets_by_src = {}
    for packet in packets:
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            if src_ip not in packets_by_src:
                packets_by_src[src_ip] = []
            packets_by_src[src_ip].append(packet)
    
    # Process each source IP
    for src_ip, ip_packets in packets_by_src.items():
        host = get_host_from_ip(net, ip_map, src_ip)
        if not host:
            info(f"No matching Mininet host for source IP {src_ip}. Skipping {len(ip_packets)} packets.\n")
            continue
            
        info(f"Sending {len(ip_packets)} packets from {src_ip} using {host.name}...\n")
        
        # Use ping to verify connectivity first
        host.cmd(f"ping -c 1 10.0.0.2 > /dev/null 2>&1")
        
        # Create a Python script to send packets one by one with error handling
        # Note: We use double braces for actual braces in the script to avoid format issues
        script = """
import scapy.all as scapy
import socket
import time
import sys

def send_packet(packet, iface):
    try:
        # Ensure the packet has an Ethernet layer
        if scapy.Ether not in packet:
            packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / packet
            
        # Limit packet size to avoid "Message too long" error
        payload_size = len(packet) - 14  # Subtract Ethernet header
        if payload_size > 1450:  # Safer MTU size
            print(f"Packet too large ({{payload_size}} bytes), truncating...")
            packet = packet[0:1464]  # 1450 + Ethernet header
        
        # Send the packet
        scapy.sendp(packet, iface=iface, verbose=0)
        return True
    except socket.error as e:
        print(f"Error sending packet: {{e}}")
        return False
    except Exception as e:
        print(f"Unexpected error: {{e}}")
        return False

# Check if we can import scapy
try:
    print("Scapy version:", scapy.VERSION)
except Exception as e:
    print(f"Error importing scapy: {{e}}")
    sys.exit(1)

# Try to send a simple packet first
try:
    test_packet = scapy.Ether()/scapy.IP(src="10.0.0.1", dst="10.0.0.2")/scapy.ICMP()
    send_packet(test_packet, "{0}-eth0")
    print("Test packet sent successfully")
except Exception as e:
    print(f"Error sending test packet: {{e}}")

# Open the PCAP file
try:
    packets = scapy.rdpcap("{1}")
    print(f"Loaded {{len(packets)}} packets from PCAP")
except Exception as e:
    print(f"Error loading PCAP: {{e}}")
    sys.exit(1)

# Send each packet
success = 0
failed = 0
for i, packet in enumerate(packets):
    if send_packet(packet, "{0}-eth0"):
        success += 1
    else:
        failed += 1
    time.sleep(0.01)  # Small delay between packets

print(f"Sent {{success}} packets successfully, {{failed}} failed")
"""
        
        # Create a temporary PCAP file for this host
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp_pcap:
            temp_pcap_path = temp_pcap.name
            scapy.wrpcap(temp_pcap_path, ip_packets)
            
        # Fill in the script template
        script_content = script.format(host.name, temp_pcap_path)
        
        # Write the script to a temporary file
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as script_file:
            script_path = script_file.name
            script_file.write(script_content.encode())
        
        # Execute the script in the host's namespace
        result = host.cmd(f"python3 {script_path}")
        info(f"Result for {host.name}: {result}\n")
        
        # Clean up
        os.remove(script_path)
        os.remove(temp_pcap_path)
        
        # Small delay before moving to next host
        time.sleep(0.5)

def run_topology():
    setLogLevel('info')
    topo = CustomTopo()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), link=TCLink)
    net.start()
    #setup_ovs_rules()
    
    pcap_file = "sample.pcap"  # Use your existing PCAP file
    
    # IP to Mininet Host Mapping
    ip_map = {
        "h1": "10.0.0.1",
        "h2": "10.0.0.2",
        "h3": "10.0.0.3"
    }
    
    # Replay packets dynamically
    replay_packets(net, pcap_file, ip_map)
    
    # Verify OVS flows
    info("\nChecking OVS Flow Table:\n")
    os.system("sudo ovs-ofctl dump-flows s1")

    info("\nChecking OVS Port Table:\n")
    os.system("sudo ovs-ofctl dump-ports s1")
    
    CLI(net)  # Open Mininet CLI for manual testing
    net.stop()

if __name__ == "__main__":
    run_topology()