#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import sys

class ChainTopo(Topo):
    def build(self, n=3, **_opts):
        # n = número de switches en la cadena
        if n < 1: n = 1
        switches = []
        # crear switches
        for i in range(1, n+1):
            s = self.addSwitch('s%s' % i)
            switches.append(s)

        # conectar switches en cadena
        for i in range(len(switches)-1):
            self.addLink(switches[i], switches[i+1])

        # crear host en extremo izquierdo y derecho
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        # unir host 1 al primer switch, host2 al último switch
        self.addLink(h1, switches[0])
        self.addLink(h2, switches[-1])

def runChain(n):
    topo = ChainTopo(n=int(n))
    # RemoteController apuntando a POX en localhost:6633 (o 6653 según tu POX)
    c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch)
    net.addController(c0)
    net.start()
    info("*** Topology started: %s switches\n" % n)
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    if len(sys.argv) > 1:
        n = int(sys.argv[1])
    else:
        n = 3
    runChain(n)
