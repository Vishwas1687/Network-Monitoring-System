from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink

class SimpleTopo(Topo):
    def build(self):
        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Add links with bandwidth and delay constraints
        self.addLink(h1, s1, bw=10, delay='5ms')
        self.addLink(h2, s1, bw=10, delay='5ms')
        self.addLink(s1, s2, bw=20, delay='2ms')
        self.addLink(h3, s2, bw=15, delay='10ms')
        self.addLink(h4, s2, bw=15, delay='10ms')

def run_mininet():
    topo = SimpleTopo()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633), link=TCLink)
    
    net.start()

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    print("\n===== Running ICMP Ping Traffic (h1 -> h2) =====")
    h1.cmdPrint("ping -c 5 {}".format(h2.IP()))

    print("\n===== Running TCP Traffic using iperf (h1 -> h3) =====")
    h3.cmd("iperf -s &")  # Start iperf server on h3
    h1.cmdPrint("iperf -c {} -t 10".format(h3.IP()))

    print("\n===== Running UDP Traffic using hping3 (h2 -> h4) =====")
    h2.cmdPrint("hping3 -c 100 -S -p 80 {}".format(h4.IP()))

    CLI(net)  # Open Mininet CLI for further testing
    net.stop()

if __name__ == '__main__':
    run_mininet()