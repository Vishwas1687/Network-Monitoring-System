import random
import subprocess
from scapy.all import rdpcap
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.node import OVSSwitch, Host
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

# Global variable for host IPs
host_ips = []

# Function to extract unique IPs from the PCAP file
def extract_hosts_from_pcap(pcap_file):
    global host_ips
    packets = rdpcap(pcap_file)
    unique_ips = set()
    for pkt in packets:
        if pkt.haslayer("IP"):
            unique_ips.add(pkt["IP"].src)
            unique_ips.add(pkt["IP"].dst)
    host_ips = list(unique_ips)  # Convert to a list for random assignment
    return host_ips

# Tree Topology class
class TreeTopology(Topo):
    def build(self):
        global host_ips
        self.depth = 4
        self.fanout = 2
        self.host_ips = host_ips
        switches = {}  # Store all switches
        hosts = []  # Store all hosts
        
        # Create the root switch
        root_switch = self.addSwitch("s1")
        switches[1] = [root_switch]  # Level 1
        
        # Create the tree recursively
        switch_count = 1
        for level in range(2, self.depth + 1):
            switches[level] = []
            for parent_switch in switches[level - 1]:
                for _ in range(self.fanout):
                    switch_count += 1
                    switch = self.addSwitch(f"s{switch_count}")
                    switches[level].append(switch)
                    # Use r2q parameter to fix HTB quantum warning
                    self.addLink(parent_switch, switch, cls=TCLink, bw=1000, params1={'r2q': 100000}, params2={'r2q': 100000})
        
        # Assign extracted hosts randomly to the last level switches
        last_level_switches = switches[self.depth]
        random.shuffle(last_level_switches)  # Shuffle to randomize host placement
        
        # Make sure we have host IPs to work with
        if not self.host_ips:
            print("WARNING: No host IPs found, adding dummy host")
            self.host_ips = ["10.0.0.1"]  # Add at least one host if no IPs found
            
        for i, ip in enumerate(self.host_ips):
            host = self.addHost(f"h{i+1}", ip=f"{ip}/24")
            hosts.append(host)
            switch = random.choice(last_level_switches)
            # Use r2q parameter to fix HTB quantum warning
            self.addLink(host, switch, cls=TCLink, bw=100, params1={'r2q': 10000}, params2={'r2q': 10000})

# Function to replay PCAP traffic from Mininet
def replay_traffic(net, pcap_file):
    print("Net Hosts:", net.hosts)
    if not net.hosts:
        print("ERROR: No hosts found in the network")
        return
        
    host = random.choice(net.hosts)  # Choose a random host to replay traffic
    interface = f"{host.name}-eth0"
    print(f"Replaying traffic from {pcap_file} on {host.name} ({interface})...")
    
    # Copy the pcap file to Mininet filesystem (if needed)
    subprocess.run(["cp", pcap_file, "/tmp/traffic.pcap"])
    
    # Run tcpreplay inside the Mininet host
    host.cmd(f"tcpreplay -i {interface} /tmp/traffic.pcap &")

# Main function to run Mininet
def run_mininet(pcap_file):
    global host_ips
    setLogLevel("info")
    subprocess.run(["sudo", "mn", "-c"])
    
    # Step 1: Extract hosts from the PCAP file
    extracted_ips = extract_hosts_from_pcap(pcap_file)
    print(f"Extracted {len(extracted_ips)} unique IPs: {extracted_ips}")
    
    # Step 2: Create Mininet with the tree topology
    topo = TreeTopology()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), link=TCLink)
    net.start()
    print("Mininet network started.")
    
    # Step 3: Replay traffic from a randomly chosen host
    replay_traffic(net, pcap_file)
    
    # Step 4: Start Mininet CLI for manual inspection
    CLI(net)
    
    # Step 5: Stop Mininet when done
    net.stop()

# Run the script with a given PCAP file
if __name__ == "__main__":
    pcap_file = "traffic.pcap"  # Set your PCAP file here
    run_mininet(pcap_file)