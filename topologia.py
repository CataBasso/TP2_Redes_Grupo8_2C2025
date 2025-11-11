#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import sys

class ChainTopo(Topo):
    def build(self, n=4, **_opts):
        """
        Topología en cadena con:
        - n switches conectados en serie
        - 4 hosts fijos:
            h1, h2 conectados al primer switch (s1)
            h3, h4 conectados al último switch (sN)
        """
        if n < 2:
            raise ValueError("La topología requiere al menos 2 switches")

        # Crear switches
        switches = [self.addSwitch(f's{i}') for i in range(1, n+1)]

        # Conectar switches en cadena
        for i in range(len(switches) - 1):
            self.addLink(switches[i], switches[i+1])

        # Crear hosts (siempre 4)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Conectar hosts de la izquierda al primer switch
        self.addLink(h1, switches[0])
        self.addLink(h2, switches[0])

        # Conectar hosts de la derecha al último switch
        self.addLink(h3, switches[-1])
        self.addLink(h4, switches[-1])

# Crea la topología en cadena con n switches, 
# Arranca Mininet conectando los switches a un RemoteController en 127.0.0.1:6633, 
# Abre la CLI para interacción y detiene la red al salir.
def runChain(n):
    topo = ChainTopo(n=int(n))
    c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch)
    net.addController(c0)
    net.start()
    info(f"*** Topology started: {n} switches, 4 hosts\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    runChain(n)

# Registrar topología para uso con --custom
topos = { 'chain': (lambda n: ChainTopo(n=int(n))) }