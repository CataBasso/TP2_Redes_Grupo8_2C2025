#!/usr/bin/env python3
"""
Script completo para probar las reglas del firewall (1..3).

Uso:
  1) Arrancar POX (desde la raíz del repo, SIN sudo):
     PYTHONPATH=. python3 pox/pox.py log.level --DEBUG pox_ext.l2_learning_custom > pox.log 2>&1 &

  2) Ejecutar este script con sudo (Mininet necesita privilegios):
     sudo python3 test_firewall_runner.py n

El script:
 - Arranca la topología ChainTopo(n)
 - Fuerza aprendizaje de MACs (pings/ARP)
 - Ejecuta las 3 pruebas y muestra OK/FAIL
"""
import sys
import time
import os
import re
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from topologia import ChainTopo

def safe(cmd):
    return cmd.replace('\n','; ')

def run_tests(n=4):
    setLogLevel('info')
    topo = ChainTopo(n=int(n))
    c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch)
    net.addController(c0)

    info("Starting Mininet...\n")
    net.start()
    time.sleep(1)

    info("Getting hosts...\n")
    try:
        h1, h2, h3, h4 = net.get('h1','h2','h3','h4')
    except Exception as e:
        info("Error: hosts not found: %s\n" % e)
        net.stop()
        return

    # Forzar aprendizaje de MACs/IPs (ping/ARP)
    info("Forzando aprendizaje de MACs (ping/arp)...\n")
    h1.cmd('arp -n || true')
    h2.cmd('arp -n || true')
    h3.cmd('arp -n || true')
    h4.cmd('arp -n || true')
    # ping neighbours to populate controller tables
    h1.cmd('ping -c 1 10.0.0.2 > /dev/null 2>&1 || true')
    h2.cmd('ping -c 1 10.0.0.3 > /dev/null 2>&1 || true')
    h3.cmd('ping -c 1 10.0.0.4 > /dev/null 2>&1 || true')
    h4.cmd('ping -c 1 10.0.0.1 > /dev/null 2>&1 || true')
    time.sleep(0.8)

    results = []

    # TEST 1: Bloqueo puerto 80 (HTTP) - h1 -> h3:80
    info("\n--- TEST 1: Puerto 80 (HTTP) debe BLOQUEARSE ---\n")
    h3.cmd('pkill -f "http.server" || true')
    h3.cmd('python3 -m http.server 80 > /tmp/_http_server.log 2>&1 &')
    time.sleep(0.5)
    out = h1.cmd('timeout 3 curl -s -I http://10.0.0.3:80 || true')
    blocked = (out.strip() == "")
    results.append(("Regla 1 (dst port 80)", blocked))
    info("  Resultado: %s\n" % ("BLOCKED" if blocked else "ALLOWED"))
    h3.cmd('pkill -f "http.server" || true')

    # TEST 2: Bloqueo UDP 5001 desde h1 (host_port_protocol_block)
    info("\n--- TEST 2: UDP puerto 5001 (h1 -> h3) debe BLOQUEARSE ---\n")
    # servidor UDP simple en h3 que responde una vez
    h3.cmd('pkill -f "udp_echo_server" || true')
    server_py = (
        "import socket\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        "s.bind(('',5001))\n"
        "try:\n"
        "  data,addr=s.recvfrom(4096)\n"
        "  s.sendto(b'OK',addr)\n"
        "except:\n"
        "  pass\n"
        "s.close()\n"
    )
    h3.cmd('python3 -u - <<PY > /tmp/udp_srv.log 2>&1 &\n' + server_py + '\nPY')
    time.sleep(0.4)
    # cliente en h1
    client = h1.cmd('python3 -u - <<PY\nimport socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.settimeout(2)\ns.sendto(b"ping", ("10.0.0.3",5001))\ntry:\n  data,addr=s.recvfrom(4096)\n  print(data.decode())\nexcept Exception:\n  print("NO_REPLY")\nPY')
    blocked2 = ('NO_REPLY' in client)
    results.append(("Regla 2 (h1 -> UDP 5001)", blocked2))
    info("  Resultado: %s (cliente output: %s)\n" % ("BLOCKED" if blocked2 else "ALLOWED", client.strip()))
    h3.cmd('pkill -f "udp_echo_server" || true')

    # TEST 3: Bloqueo host_pair (h1 <-> h3)
    info("\n--- TEST 3: Bloqueo h1 <-> h3 debe BLOQUEARSE ---\n")
    ping_out = h1.cmd('ping -c 3 10.0.0.3')

    # parsear % de packet loss de la salida del ping
    m = re.search(r'(\d+)% packet loss', ping_out)
    loss = int(m.group(1)) if m else None

    blocked3 = (loss == 100)
    results.append(("Regla 3 (h1 <-> h3)", blocked3))
    info("  Resultado: %s (loss=%s%%)\n" % ("BLOCKED" if blocked3 else "ALLOWED", loss if loss is not None else 'n/a'))

    # Resumen
    info("\n=== Resumen de pruebas ===\n")
    for name, ok in results:
        info(f"{name}: {'OK (blocked)' if ok else 'FAIL (allowed)'}\n")

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Este script debe ejecutarse con sudo (Mininet necesita privilegios).")
        sys.exit(1)
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    run_tests(n)