import random
import subprocess
import time
import os
from scapy.all import rdpcap, IP
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.node import OVSSwitch, Host
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

host_ips = []
# Extracts unique IPs and IP pairs (src->dst) from the PCAP file
def extract_info_from_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    unique_ips = set()
    ip_pairs = []
    
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            unique_ips.add(src_ip)
            unique_ips.add(dst_ip)
            # Store the source-destination IP pair
            ip_pairs.append((src_ip, dst_ip))
            
    return list(unique_ips), ip_pairs

# Tree Topology class
class TreeTopology(Topo):
    def build(self):
        self.depth = 4
        self.fanout = 2
        self.host_ips = host_ips
        self.ip_to_host = {}  # Mapping of IP to host object name
        switches = {}  # Store all switches based on level as key
        hosts = []  # Store all hosts
        
        # Creating the root switch
        root_switch = self.addSwitch("s1")
        switches[1] = [root_switch]  # Level 1
        
        # Creating the tree topology 
        switch_count = 1
        for level in range(2, self.depth + 1):
            switches[level] = []
            for parent_switch in switches[level - 1]:
                for _ in range(self.fanout):
                    switch_count += 1
                    switch = self.addSwitch(f"s{switch_count}")
                    switches[level].append(switch)
                    self.addLink(parent_switch, switch, cls=TCLink, bw=1000)  # switch-switch links
        
        # Ensuring the PCAP file has at least one unique IP
        if not self.host_ips:
            # Adding some host_ips in case there are no unique IPs in PCAP file
            self.host_ips = [f"10.0.0.{i}" for i in range(1, 11)]
            print(f"No valid IPs found in PCAP, adding {len(self.host_ips)} default hosts")
            
        # Assigning extracted hosts randomly to the last level switches
        last_level_switches = switches[self.depth]
        if not last_level_switches:
            print("Error: No leaf switches available for host connection")
            return
            
        random.shuffle(last_level_switches)  # Shuffling to randomize host placement
        
        print(f"Creating {len(self.host_ips)} hosts with IPs: {self.host_ips}")
        for i, ip in enumerate(self.host_ips):
            host_name = f"h{i+1}"
            host = self.addHost(host_name, ip=f"{ip}/24")
            hosts.append(host)
            self.ip_to_host[ip] = host_name  # Store mapping of IP to host name
            print("IP - Hostname:", ip, host_name)
            switch = random.choice(last_level_switches)
            self.addLink(host, switch, cls=TCLink, bw=100)  # Host-switch links

# Replaying PCAP traffic with original source and destination
import subprocess

def replay_traffic(net, pcap_file, pcap_id, ip_to_host_map, ip_pairs):
    if not ip_pairs:
        print(f"No valid IP pairs found in {pcap_file}")
        return False

    success = False  # Track if at least one replay was successful

    for src_ip, dst_ip in ip_pairs:
        if src_ip in ip_to_host_map and dst_ip in ip_to_host_map:
            src_host_name = ip_to_host_map[src_ip]
            dst_host_name = ip_to_host_map[dst_ip]
            
            source_host = net.get(src_host_name)
            source_interface = f"{source_host.name}-eth0"

            print(f"Replaying traffic from {src_host_name}({src_ip}) to {dst_host_name}({dst_ip}) using {pcap_file}")

            # Command to filter packets in memory and replay them directly
            filter_replay_cmd = f"tcpdump -r {pcap_file} -w - 'host {src_ip} and host {dst_ip}' | tcpreplay --intf1={source_interface} --loop=1 -"
            source_host.cmd(filter_replay_cmd)

            success = True  # Mark as successful if at least one replay runs

        else:
            print(f"Could not find matching hosts for IPs {src_ip} -> {dst_ip}")

    return success  # Return True if at least one replay was successful


# Starting multiple PCAP files together using original IP pairs
def start_multiple_replays(net, pcap_files, ip_to_host_map, all_ip_pairs, num_replays=1):
    if not net.hosts or len(net.hosts) < 2:
        print("Error: Need at least 2 hosts to replay traffic")
        return False
    
    if not pcap_files:
        print("Error: No PCAP files provided")
        return False
    
    if not all_ip_pairs:
        print("Error: No valid IP pairs found in PCAP files")
        return False
        
    print(f"Starting {num_replays} parallel traffic replays based on original PCAP IP pairs...")
    
    # Starting specified number of replays
    for i in range(num_replays):
        # Choosing PCAP files in order from the provided list
        pcap_index = i % len(pcap_files)
        pcap_file = pcap_files[pcap_index]
        
        # Use the corresponding IP pairs for this PCAP
        ip_pairs = all_ip_pairs[pcap_index]
        
        # Starting the traffic replay with original IPs
        replay_traffic(net, pcap_file, i, ip_to_host_map, ip_pairs)
        time.sleep(0.5)
        
    print(f"Successfully started {num_replays} background traffic replays")
    return True

# Main function to run Mininet
def run_mininet(pcap_files):
    setLogLevel("info")
    
    # Step 1: Extracting hosts and IP pairs from all PCAP files
    all_host_ips = set()
    all_ip_pairs = []
    
    for pcap_file in pcap_files:
        unique_ips, ip_pairs = extract_info_from_pcap(pcap_file)
        all_host_ips.update(unique_ips)
        all_ip_pairs.append(ip_pairs)
    
    global host_ips
    host_ips = list(all_host_ips)
    print(f"Extracted {len(host_ips)} unique IPs from all PCAP files")
    
    # Step 2: Creating Mininet with the tree topology
    topo = TreeTopology()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), link=TCLink)
    
    try:
        net.start()
        print("Mininet network started.")
        print(f"Network has {len(net.hosts)} hosts and {len(net.switches)} switches")
        
        # Create IP to host name mapping for the running network
        ip_to_host_map = {}
        for host in net.hosts:
            ip = host.IP().split('/')[0]  # Remove subnet mask
            ip_to_host_map[ip] = host.name
            print(f"Host: {host.name}, IP: {ip}")
        
        # Step 3: Starting multiple traffic replays in parallel using original IP pairs
        start_multiple_replays(net, pcap_files, ip_to_host_map, all_ip_pairs)
        
        # Step 4: Starting Mininet CLI for manual inspection
        CLI(net)
    except Exception as e:
        print(f"Error in Mininet: {e}")
    finally:
        # Step 5: Stopping Mininet when done
        print("Stopping Mininet network...")
        net.stop()

# Running the script with multiple PCAP files
if __name__ == "__main__":
    # List of PCAP files to use
    pcap_directory = "."  # Current directory
    pcap_files = [os.path.join(pcap_directory, f) for f in os.listdir(pcap_directory) 
                  if f.endswith('.pcap')]
    
    if not pcap_files:
        print("No PCAP files found. Using a default file.")
        pcap_files = ["traffic.pcap"]
    
    print(f"Found PCAP files: {pcap_files}")
    run_mininet(pcap_files)