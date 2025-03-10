#             s1
#           /    \
#          s2     s3
#         / \     /   \
#       s4  s5   s6     s7
#       /   | \    \   |  \
#     h1    h2 h3   h4 h5 h6
#
#     Depth = 2, Fanout = 2(Only for switches). Hosts are randomly assigned 
#     to random leaf switches of different fanout
 
import random
import subprocess
import time
import os
from scapy.all import rdpcap
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.node import OVSSwitch, Host
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

host_ips = []
# Extracts unique IPs from the PCAP file
def extract_hosts_from_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    unique_ips = set()
    for pkt in packets:
        if pkt.haslayer("IP"):
            unique_ips.add(pkt["IP"].src)
            unique_ips.add(pkt["IP"].dst)
    host_ips = list(unique_ips) 
    return host_ips

# Tree Topology class
class TreeTopology(Topo):

    def build(self):
        self.depth = 4
        self.fanout = 2
        self.host_ips = host_ips
        switches = {}  # Store all switches based on level as key
        hosts = []  # Store all hosts
        
        # Creating the root switch
        root_switch = self.addSwitch("s1")
        switches[1] = [root_switch]  # Level 1
        
        # Creating the root topology 
        switch_count = 1
        for level in range(2, self.depth + 1):
            switches[level] = []
            for parent_switch in switches[level - 1]:
                for _ in range(self.fanout):
                    switch_count += 1
                    switch = self.addSwitch(f"s{switch_count}")
                    switches[level].append(switch)
                    self.addLink(parent_switch, switch, cls=TCLink, bw=1000)  # switch-switch links
        
        # Ensuring the PCAP file has atleast one unique IP
        if not self.host_ips:
            # Adding some host_ips incase there are no unique IPs in PCAP file
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
            host = self.addHost(f"h{i+1}", ip=f"{ip}/24")
            hosts.append(host)
            switch = random.choice(last_level_switches)
            self.addLink(host, switch, cls=TCLink, bw=100)  # Host-switch links

# Replaying PCAP traffic from one host to another
def replay_traffic(source_host, target_host, pcap_file, pcap_id):
    source_interface = f"{source_host.name}-eth0"
    temp_pcap = f"/tmp/traffic_{pcap_id}.pcap"
    print(f"Replaying traffic from {source_host.name} to {target_host.name} using {pcap_file}")
    
    # Copy the pcap file to Mininet filesystem
    subprocess.run(["cp", pcap_file, temp_pcap])
    
    # --loop=0 means infinite replay, --unique-ip spreads the traffic,
    # --intf1 specifies the interface
    cmd = f"tcpreplay --loop=0 --unique-ip --intf1={source_interface} {temp_pcap} &"
    source_host.cmd(cmd)
    return True

# Starting multiple PCAP files together
def start_multiple_replays(net, pcap_files, num_replays=5):
    if not net.hosts or len(net.hosts) < 2:
        print("Error: Need at least 2 hosts to replay traffic")
        return False
    
    if not pcap_files:
        print("Error: No PCAP files provided")
        return False
        
    print(f"Starting {num_replays} parallel traffic replays...")
    
    # Starting specified number of replays
    for i in range(num_replays):
        # Choose random source and target hosts 
        source_host = random.choice(net.hosts)
        target_host = random.choice([h for h in net.hosts if h != source_host])
        
        # Choosing a random PCAP file from the provided list
        pcap_file = random.choice(pcap_files)
        
        # Starting the traffic replay
        replay_traffic(source_host, target_host, pcap_file, i)
        time.sleep(0.5)
        
    print(f"Successfully started {num_replays} background traffic replays")
    return True

# Main function to run Mininet
def run_mininet(pcap_files):
    setLogLevel("info")
    
    # Step 1: Extracting hosts from all PCAP files
    all_host_ips = set()
    for pcap_file in pcap_files:
        host_ips = extract_hosts_from_pcap(pcap_file)
        all_host_ips.update(host_ips)
    
    host_ips = list(all_host_ips)
    print(f"Extracted {len(host_ips)} unique IPs from all PCAP files")
    
    # Step 2: Creating Mininet with the tree topology
    topo = TreeTopology()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), link=TCLink)
    
    try:
        net.start()
        print("Mininet network started.")
        print(f"Network has {len(net.hosts)} hosts and {len(net.switches)} switches")
        
        # Printing all hosts
        for host in net.hosts:
            print(f"Host: {host.name}, IP: {host.IP()}")
        
        # Step 3: Starting multiple traffic replays in parallel
        num_replays = min(5, len(net.hosts) // 2)  # Ensuring we don't try more replays than possible
        start_multiple_replays(net, pcap_files, num_replays)
        
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