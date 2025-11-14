#!/usr/bin/env python3
import sys
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from topologia import ChainTopo

def safe(cmd):
    return cmd.replace('\n','; ')

def run_tests(n):
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

    info("\n==============================\n")
    info("   TEST REGLA 1 - DST PORT 80\n")
    info("==============================\n")

    # 1) IPv4 TCP
    info("\nTEST 1.1: IPv4 + TCP (curl) debe bloquearse\n")
    h3.cmd("pkill -f 'http.server' || true")
    h3.cmd("python3 -m http.server 80 >/tmp/http80.log 2>&1 &")
    time.sleep(0.5)

    output = h1.cmd("timeout 3 curl -s -I http://10.0.0.3:80 || true")
    blocked = (output.strip() == "")
    results.append(("IPv4 TCP", blocked))
    info("Resultado: %s\n" % ("BLOCKED" if blocked else "ALLOWED"))

    h3.cmd("pkill -f 'http.server' || true")

    # 2) IPv4 UDP
    info("\nTEST 1.2: IPv4 + UDP (netcat) debe bloquearse\n")
    h3.cmd("pkill -f 'nc -u -l 80' || true")
    h3.cmd("nohup nc -u -l 80 >/tmp/udp80.log 2>&1 &")
    time.sleep(0.5)

    output = h1.cmd("echo 'test' | nc -u -w2 10.0.0.3 80 || true")
    blocked = ("test" not in open("/tmp/udp80.log", "r").read() if 
               h1.cmd("test -f /tmp/udp80.log && echo OK") == "OK\n" else True)
    results.append(("IPv4 UDP", blocked))
    info("Resultado: %s\n" % ("BLOCKED" if blocked else "ALLOWED"))

    h3.cmd("pkill -f 'nc -u -l 80' || true")

    # 3) IPv6 TCP
    info("\nTEST 1.3: IPv6 + TCP (curl) debe bloquearse\n")
    h3.cmd("pkill -f 'http.server' || true")
    h3.cmd("python3 -m http.server 80 --bind [fd00::3] >/tmp/http80v6.log 2>&1 &")
    time.sleep(0.5)

    output = h1.cmd("timeout 3 curl -g -6 -s -I http://[fd00::3]:80 || true")
    blocked = (output.strip() == "")
    results.append(("IPv6 TCP", blocked))
    info("Resultado: %s\n" % ("BLOCKED" if blocked else "ALLOWED"))

    h3.cmd("pkill -f 'http.server' || true")

    # 4) IPv6 UDP
    info("\nTEST 1.4: IPv6 + UDP debe bloquearse\n")
    h3.cmd("rm -f /tmp/udp80v6.log")
    h3.cmd("pkill -f 'nc -u -6 -l 80' || true")
    h3.cmd("nohup nc -u -6 -l 80 > /tmp/udp80v6.log 2>&1 &")
    time.sleep(0.5)

    h1.cmd("echo 'TESTV6' | nc -u -6 -w2 fd00::3 80 || true")
    time.sleep(0.5)

    received = h3.cmd("grep -q TESTV6 /tmp/udp80v6.log && echo OK || echo NO").strip()
    blocked = (received != "OK")
    results.append(("IPv6 UDP", blocked))
    info("Resultado: %s\n" % ("BLOCKED" if blocked else "ALLOWED"))

    h3.cmd("pkill -f 'nc -u -6 -l 80' || true")

    # Resultados finales
    info("\n==============================\n")
    info("      RESULTADOS REGLA 1\n")
    info("==============================\n")
    for name, ok in results:
        info(" %-12s → %s\n" % (name, "OK" if ok else "FAIL"))

    info("\n*** Tests completados ***\n")
    net.stop()


if __name__ == "__main__":
    n = int(sys.argv[1])
    if n == None:
        print("Uso: python3 test_regla1.py <num_switches>")
        sys.exit(1)
    if n < 2:
        print("La topología requiere al menos 2 switches")
        sys.exit(1)

    run_tests(n)
