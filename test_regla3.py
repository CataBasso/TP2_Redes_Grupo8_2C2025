#!/usr/bin/env python3
import sys
import time
import re
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from topologia import ChainTopo

def run_tests(n):
    setLogLevel('info')
    topo = ChainTopo(n=int(n))
    c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch)
    net.addController(c0)

    info("\n=== Iniciando Mininet ===\n")
    net.start()
    time.sleep(1)

    h1, h2, h3, h4 = net.get('h1','h2','h3','h4')

    # Asignar IPv6
    for i,h in enumerate([h1,h2,h3,h4], start=1):
        h.cmd(f"ip -6 addr add fd00::{i}/64 dev {h.name}-eth0 || true")

    # Warm-up ARP + aprendizaje
    for h in (h1,h2,h3,h4):
        h.cmd("arp -n >/dev/null 2>&1")
    h1.cmd("ping -c1 10.0.0.3 >/dev/null 2>&1 || true")
    time.sleep(0.5)

    results = []

    info("\n========================================\n")
    info("   REGLA 3 — BLOQUEO ENTRE h1 <-> h3\n")
    info("========================================\n")

    # TEST 3.1 — IPv4 ping debe BLOQUEARSE h1 -> h3
    info("\n--- TEST 3.1: IPv4 ping h1 → h3 (debe bloquearse) ---\n")
    out = h1.cmd("ping -c 3 10.0.0.3")
    m = re.search(r'(\d+)% packet loss', out)
    loss = int(m.group(1)) if m else None
    blocked = (loss == 100)
    results.append(("IPv4 ping h1→h3", blocked))
    info("Resultado: %s (loss=%s%%)\n" % ("BLOCKED" if blocked else "ALLOWED", loss))

    # TEST 3.2 — IPv4 TCP debe BLOQUEARSE h1 -> h3
    info("\n--- TEST 3.2: IPv4 TCP (curl) h1 → h3 (debe bloquearse) ---\n")
    h3.cmd("pkill -f http.server || true")
    h3.cmd("python3 -m http.server 8081 >/tmp/h3_tcp_8081.log 2>&1 &")
    time.sleep(0.5)

    out = h1.cmd("timeout 3 curl -s -I http://10.0.0.3:8081 || true")
    blocked = (out.strip() == "")
    results.append(("IPv4 TCP h1→h3", blocked))
    info("Resultado: %s\n" % ("BLOCKED" if blocked else "ALLOWED"))
    h3.cmd("pkill -f http.server || true")

    # TEST 3.3 — IPv4 UDP debe BLOQUEARSE h1 -> h3
    info("\n--- TEST 3.3: IPv4 UDP h1 → h3 (debe bloquearse) ---\n")
    h3.cmd("rm -f /tmp/h3_udp_8081.log")
    h3.cmd("pkill -f 'nc -u -l 8081' || true")
    h3.cmd("nohup nc -u -l 8081 >/tmp/h3_udp_8081.log 2>&1 &")
    time.sleep(0.5)

    h1.cmd("echo TEST_UDP | nc -u -w1 10.0.0.3 8081")
    time.sleep(0.4)

    out = h3.cmd("grep -q TEST_UDP /tmp/h3_udp_8081.log && echo OK || echo NO").strip()
    blocked = (out != "OK")
    results.append(("IPv4 UDP h1→h3", blocked))
    info("Resultado: %s\n" % ("BLOCKED" if blocked else "ALLOWED"))
    h3.cmd("pkill -f 'nc -u -l 8081' || true")

    # TEST 3.4 — IPv6 ping debe BLOQUEARSE h1 -> h3
    info("\n--- TEST 3.4: IPv6 ping h1 → h3 (debe bloquearse) ---\n")
    out = h1.cmd("ping6 -c 3 fd00::3")
    m = re.search(r'(\d+)% packet loss', out)
    loss = int(m.group(1)) if m else None
    blocked = (loss == 100)
    results.append(("IPv6 ping h1→h3", blocked))
    info("Resultado: %s (loss=%s%%)\n" % ("BLOCKED" if blocked else "ALLOWED", loss))

    # TEST 3.5 — IPv6 TCP debe BLOQUEARSE h1 -> h3
    info("\n--- TEST 3.5: IPv6 TCP h1 → h3 (debe bloquearse) ---\n")
    h3.cmd("pkill -f http.server || true")
    h3.cmd("python3 -m http.server 8082 --bind fd00::3 >/tmp/h3_tcp6_8082.log 2>&1 &")
    time.sleep(0.5)

    out = h1.cmd("timeout 3 curl -g -6 -s -I http://[fd00::3]:8082 || true")
    blocked = (out.strip() == "")
    results.append(("IPv6 TCP h1→h3", blocked))
    info("Resultado: %s\n" % ("BLOCKED" if blocked else "ALLOWED"))
    h3.cmd("pkill -f http.server || true")

    # TEST 3.6 — IPv6 UDP debe BLOQUEARSE h1 -> h3
    info("\n--- TEST 3.6: IPv6 UDP h1 → h3 (debe bloquearse) ---\n")
    h3.cmd("rm -f /tmp/h3_udp6_8082.log")
    h3.cmd("pkill -f 'nc -u -6 -l 8082' || true")
    h3.cmd("nohup nc -u -6 -l 8082 >/tmp/h3_udp6_8082.log 2>&1 &")
    time.sleep(0.5)

    h1.cmd("echo TESTV6 | nc -u -6 -w1 fd00::3 8082")
    time.sleep(0.4)

    out = h3.cmd("grep -q TESTV6 /tmp/h3_udp6_8082.log && echo OK || echo NO").strip()
    blocked = (out != "OK")
    results.append(("IPv6 UDP h1→h3", blocked))
    info("Resultado: %s\n" % ("BLOCKED" if blocked else "ALLOWED"))
    h3.cmd("pkill -f 'nc -u -6 -l 8082' || true")

    #############################################
    # CASOS QUE DEBEN FUNCIONAR — NO BLOQUEADOS
    #############################################

    info("\n========================================\n")
    info("   CASOS DE ÉXITO (NO debe bloquear)\n")
    info("========================================\n")

    # 3.7  IPv4 ICMP permitido: h1 → h2
    info("\n--- TEST 3.7: h1 → h2 IPv4 ping (permitido) ---\n")
    out = h1.cmd("ping -c2 10.0.0.2")
    loss = int(re.search(r'(\d+)% packet loss', out).group(1))
    allowed = (loss < 100)
    results.append(("IPv4 ICMP h1→h2", allowed))
    info("Resultado: %s\n" % ("ALLOWED" if allowed else "BLOCKED"))

    # 3.8  IPv6 ICMP permitido: h1 → h2
    info("\n--- TEST 3.8: h1 → h2 IPv6 ping (permitido) ---\n")
    out = h1.cmd("ping6 -c2 fd00::2")
    loss = int(re.search(r'(\d+)% packet loss', out).group(1))
    allowed = (loss < 100)
    results.append(("IPv6 ICMP h1→h2", allowed))
    info("Resultado: %s\n" % ("ALLOWED" if allowed else "BLOCKED"))

    # 3.9  IPv4 TCP permitido: h3 → h4
    info("\n--- TEST 3.9: h3 → h4 TCP (permitido) ---\n")
    h4.cmd("pkill -f http.server || true")
    h4.cmd("python3 -m http.server 9000 >/tmp/h4_tcp9000.log 2>&1 &")
    time.sleep(0.5)
    out = h3.cmd("timeout 3 curl -s -I http://10.0.0.4:9000 || true")
    allowed = (out.strip() != "")
    results.append(("IPv4 TCP h3→h4", allowed))
    info("Resultado: %s\n" % ("ALLOWED" if allowed else "BLOCKED"))
    h4.cmd("pkill -f http.server || true")

    # 3.10 IPv6 TCP permitido: h3 → h4
    info("\n--- TEST 3.10: h3 → h4 IPv6 TCP (permitido) ---\n")
    h4.cmd("pkill -f http.server || true")
    h4.cmd("python3 -m http.server 9001 --bind fd00::4 >/tmp/h4_tcp9001.log 2>&1 &")
    time.sleep(0.5)
    out = h3.cmd("timeout 3 curl -g -6 -s -I http://[fd00::4]:9001 || true")
    allowed = (out.strip() != "")
    results.append(("IPv6 TCP h3→h4", allowed))
    info("Resultado: %s\n" % ("ALLOWED" if allowed else "BLOCKED"))
    h4.cmd("pkill -f http.server || true")

    # 3.11 IPv4 UDP permitido: h2 → h4
    info("\n--- TEST 3.11: h2 → h4 UDP (permitido) ---\n")
    h4.cmd("rm -f /tmp/h4_udp9000.log")
    h4.cmd("nohup nc -u -l 9000 >/tmp/h4_udp9000.log 2>&1 &")
    time.sleep(0.5)
    h2.cmd("echo PERMIT | nc -u -w1 10.0.0.4 9000")
    time.sleep(0.4)
    out = h4.cmd("grep -q PERMIT /tmp/h4_udp9000.log && echo OK || echo NO").strip()
    allowed = (out == "OK")
    results.append(("IPv4 UDP h2→h4", allowed))
    info("Resultado: %s\n" % ("ALLOWED" if allowed else "BLOCKED"))
    h4.cmd("pkill -f 'nc -u -l 9000' || true")

    # 3.12 IPv6 UDP permitido: h2 → h4
    info("\n--- TEST 3.12: h2 → h4 IPv6 UDP (permitido) ---\n")
    h4.cmd("rm -f /tmp/h4_udp9001.log")
    h4.cmd("pkill -f 'nc -u -6 -l 9001' || true")
    h4.cmd("nohup nc -u -6 -l 9001 >/tmp/h4_udp9001.log 2>&1 &")
    time.sleep(0.5)

    h2.cmd("echo PERMIT6 | nc -u -6 -w1 fd00::4 9001")
    time.sleep(0.4)

    out = h4.cmd("grep -q PERMIT6 /tmp/h4_udp9001.log && echo OK || echo NO").strip()
    allowed = (out == "OK")
    results.append(("IPv6 UDP h2→h4", allowed))
    info("Resultado: %s\n" % ("ALLOWED" if allowed else "BLOCKED"))
    h4.cmd("pkill -f 'nc -u -6 -l 9001' || true")

    # RESUMEN
    info("\n==============================\n")
    info("     RESULTADOS REGLA 3\n")
    info("==============================\n")
    for name, ok in results:
        info(" %-20s → %s\n" % (name, "OK" if ok else "FAIL"))

    net.stop()
    info("\n*** Tests completados ***\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 test_regla3.py <num_switches>")
        sys.exit(1)
    run_tests(int(sys.argv[1]))
