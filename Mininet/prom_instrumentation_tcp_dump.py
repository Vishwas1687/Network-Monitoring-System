import random
import netaddr
import threading
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.node import OVSKernelSwitch, RemoteController
import os
import scapy.all as scapy
import tempfile
import time
from prometheus_client import start_http_server, Gauge

global_ip_map = {}
tcp_syn_count = Gauge('tcp_syn_packets', 'Number of TCP SYN packets processed')

def is_public_ip(ip):
    ip_obj = netaddr.IPAddress(ip)
    return not (ip_obj.is_private() or ip_obj.is_multicast() or ip_obj.is_reserved() or ip_obj.is_loopback())

def extract_public_ips(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    public_ips = set()
    for packet in packets:
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            public_ips.add(src_ip)
    return list(public_ips)

def generate_ip_mapping(public_ips):
    return {public_ip: f'10.0.0.{i+1}' for i, public_ip in enumerate(public_ips)}

class RandomTopo(Topo):
    def build(self, host_count):
        switches = [self.addSwitch(f's{i+1}', cls=OVSKernelSwitch) for i in range(10)]
        for i in range(1, host_count + 1):
            host = self.addHost(f'h{i}', ip=f'10.0.0.{i}', mac=f'00:00:00:00:00:{i:02x}')
            self.addLink(host, random.choice(switches))
        for _ in range(15):
            s1, s2 = random.sample(switches, 2)
            self.addLink(s1, s2)

def get_host_from_ip(net, src_ip):
    private_ip = global_ip_map.get(src_ip)
    if private_ip:
        for host in net.hosts:
            if host.IP() == private_ip:
                return host
    return None

def replay_packets(net, pcap_file):
    packets = scapy.rdpcap(pcap_file)
    packets_by_src = {}
    syn_count = 0

    for packet in packets:
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            if src_ip not in packets_by_src:
                packets_by_src[src_ip] = []
            packets_by_src[src_ip].append(packet)
            if scapy.TCP in packet and packet[scapy.TCP].flags & 0x02:
                syn_count += 1
    
    tcp_syn_count.set(syn_count)
    
    for src_ip, ip_packets in packets_by_src.items():
        host = get_host_from_ip(net, src_ip)
        if not host:
            continue
        info(f"Replaying {len(ip_packets)} packets from {global_ip_map.get(src_ip)} on {host.name}...\n")
        modified_ip_packets = []
        for pkt in ip_packets:
            if scapy.IP in pkt:
                pkt[scapy.IP].src = global_ip_map.get(pkt[scapy.IP].src)
                pkt[scapy.IP].dst = global_ip_map.get(pkt[scapy.IP].dst)
                del pkt[scapy.IP].chksum
                modified_ip_packets.append(pkt)
        temp_pcap = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        scapy.wrpcap(temp_pcap.name, modified_ip_packets)
        temp_script = tempfile.NamedTemporaryFile(suffix='.py', delete=False)
        script_content = f"""
import os
import scapy.all as scapy

def send_packet(packet, iface):
    try:
        print(f"Sending packet with source IP: {{packet[scapy.IP].src}} and destination IP: {{packet[scapy.IP].dst}}");
        scapy.sendp(packet, iface=iface, verbose=0)
        print(f"Packet sent successfully on interface {{iface}}")
    except Exception as e:
        print(f'Error in sending packet: {{e}}')

print("Starting packet replay...")
packets = scapy.rdpcap('{temp_pcap.name}')
print(f"Total packets to replay: {{len(packets)}}")
for pkt in packets:
    send_packet(pkt, '{host.name}-eth0')
print("Packet replay completed.")
"""
        temp_script.write(script_content.encode())
        temp_script.close()
        output = host.cmd(f'python3 {temp_script.name}')
        print(output)
        os.remove(temp_script.name)
        os.remove(temp_pcap.name)
        time.sleep(0.5)

def run_topology():
    global global_ip_map
    setLogLevel('info')
    start_http_server(8081)
    pcap_files = [f for f in os.listdir('.') if f.startswith('traffic') and f.endswith('.pcap')]
    all_public_ips = set()
    for pcap_file in pcap_files:
        all_public_ips.update(extract_public_ips(pcap_file))
    if not all_public_ips:
        info("No valid public IPs found in the PCAP files.\n")
        return
    global_ip_map.update(generate_ip_mapping(list(all_public_ips)))
    topo = RandomTopo(len(global_ip_map))
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), link=TCLink)
    net.start()
    info(f"Mapped {len(global_ip_map)} public IPs to private subnet:\n{global_ip_map}\n")
    threads = []
    for pcap_file in pcap_files:
        thread = threading.Thread(target=replay_packets, args=(net, pcap_file))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    info("\nMetrics Exporter running on port 8081.\n")
    info("\nChecking OVS Flow Table:\n")
    os.system("sudo ovs-ofctl dump-flows s1")
    info("\nChecking OVS Port Table:\n")
    os.system("sudo ovs-ofctl dump-ports s1")
    CLI(net)
    net.stop()

if __name__ == "__main__":
    run_topology()
