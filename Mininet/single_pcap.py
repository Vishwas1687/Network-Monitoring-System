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
            public_ips.add(src_ip)
            # if is_public_ip(src_ip):
            #     public_ips.add(src_ip)
    return list(public_ips)

# Generate a mapping of public IPs to private IPs
def generate_ip_mapping(public_ips):
    """Map public IP addresses to private 10.0.0.x addresses."""
    return {public_ip: f'10.0.0.{i+1}' for i, public_ip in enumerate(public_ips)}

# Random topology with hosts and switches
class RandomTopo(Topo):
    """Random topology with 10 switches and dynamically assigned hosts."""
    def build(self, host_count):
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
def get_host_from_ip(net, src_ip):
    """Find corresponding Mininet host for a given private IP."""
    private_ip = ip_map_global.get(src_ip)
    if private_ip:
        for host in net.hosts:
            if host.IP() == private_ip:
                return host
    return None

# Replay packets using mapped private IPs
def replay_packets(net, pcap_file):
    """Replay packets dynamically based on source IP mapping using Scapy."""
    packets = scapy.rdpcap(pcap_file)
    packets_by_src = {}

    # Group packets by original public IP
    for packet in packets:
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            if src_ip not in packets_by_src:
                packets_by_src[src_ip] = []  # Initialize list if key doesn't exist

            packets_by_src[src_ip].append(packet)  # Append packet to the list

    # Replay packets for each source IP
    for src_ip, ip_packets in packets_by_src.items():
        host = get_host_from_ip(net, src_ip)
        if not host:
            continue
        
        info(f"Replaying {len(ip_packets)} packets from {ip_map_global.get(src_ip)} on {host.name}...\n")
        
        # Modify packets with new private IPs
        modified_ip_packets = []
        for pkt in ip_packets:
            if scapy.IP in pkt:
                pkt[scapy.IP].src = ip_map_global.get(pkt[scapy.IP].src)
                # print("Pre Destination packet:", pkt[scapy.IP].dst)
                pkt[scapy.IP].dst = ip_map_global.get(pkt[scapy.IP].dst)
                # print("Destination packet:",pkt[scapy.IP].dst)
                del pkt[scapy.IP].chksum  # Recalculate checksum
                modified_ip_packets.append(pkt)      

        # Save modified packets to a temp file
        temp_pcap = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        scapy.wrpcap(temp_pcap.name, modified_ip_packets)  # Write modified packets
        
        # Generate replay script
        script_content = f"""
import os
import scapy.all as scapy

def send_packet(packet, iface):
    try:
        print(f"Sending packet with source IP: {{packet[scapy.IP].src}} and destination IP: {{packet[scapy.IP].dst}}")
        scapy.sendp(packet, iface=iface, verbose=0)
        print(f"Packet sent successfully on interface {{iface}}")
    except Exception as e:
        print(f'Error in sending packet: {{e}}')

print("Starting packet replay...")
packets = scapy.rdpcap('{temp_pcap.name}')  # Read modified packets
print(f"Total packets to replay: {{len(packets)}}")

for pkt in packets:
    send_packet(pkt, '{host.name}-eth0')

print("Packet replay completed.")
"""
        temp_script = tempfile.NamedTemporaryFile(suffix='.py', delete=False)
        temp_script.write(script_content.encode())
        temp_script.close()
        
        # Run the replay script on the host
        output = host.cmd(f'python3 {temp_script.name}')
        print(output)
        
        # Cleanup
        os.remove(temp_script.name)
        os.remove(temp_pcap.name)
        time.sleep(0.5)

# Run the Mininet topology and replay packets
def run_topology(pcap_file):
    """Run the Mininet topology and replay packets."""
    global ip_map_global
    setLogLevel('info')

    public_ips = extract_public_ips(pcap_file)
    if not public_ips:
        info("No valid public IPs found in the PCAP file.\n")
        return

    # Generate and store IP mapping
    ip_map_global.update(generate_ip_mapping(public_ips))
    
    # Setup Mininet topology
    topo = RandomTopo(len(ip_map_global))
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), link=TCLink)
    net.start()

    info(f"Mapped {len(ip_map_global)} public IPs to private subnet:\n{ip_map_global}\n")
    
    # Replay packets
    replay_packets(net, pcap_file)

    # Verify OVS flows
    info("\nChecking OVS Flow Table:\n")
    os.system("sudo ovs-ofctl dump-flows s1")

    info("\nChecking OVS Port Table:\n")
    os.system("sudo ovs-ofctl dump-ports s1")

    # Start CLI
    CLI(net)
    net.stop()

if __name__ == "__main__":
    pcap_file = "traffic_1.pcap"  # Replace with your PCAP file
    run_topology(pcap_file)