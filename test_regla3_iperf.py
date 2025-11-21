#!/usr/bin/env python3
"""
Test de Regla 3 con iperf: Bloquear comunicación h1 ↔ h3
Replica exactamente test_regla3.py pero con iperf donde sea posible
"""
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

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    # Asignar IPv6
    for i, h in enumerate([h1, h2, h3, h4], start=1):
        h.cmd(f"ip -6 addr add fd00::{i}/64 dev {h.name}-eth0 || true")

    # Warm-up ARP + aprendizaje
    for h in (h1, h2, h3, h4):
        h.cmd("arp -n >/dev/null 2>&1")
    h1.cmd("ping -c1 10.0.0.3 >/dev/null 2>&1 || true")
    time.sleep(0.5)

    results = []

    info("\n" + "="*60 + "\n")
    info("   REGLA 3 — BLOQUEO ENTRE h1 ↔ h3 (IPERF)\n")
    info("="*60 + "\n")

    # TEST 3.1: IPv4 ping h1→h3 (debe bloquearse)
    info("\n--- TEST 3.1: IPv4 ping h1 → h3 (debe bloquearse) ---\n")
    out = h1.cmd("ping -c 3 10.0.0.3")
    m = re.search(r'(\d+)% packet loss', out)
    loss = int(m.group(1)) if m else None
    blocked = (loss == 100)
    results.append(("IPv4 ping h1→h3", blocked))
    info(f"Resultado: {'BLOCKED' if blocked else 'ALLOWED'} (loss={loss}%)\n")

    # TEST 3.2: IPv4 TCP h1→h3 con iperf (debe bloquearse)
    info("\n--- TEST 3.2: IPv4 TCP (iperf) h1 → h3 (debe bloquearse) ---\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -p 8081 > /tmp/iperf_h3_8081.log 2>&1 &")
    time.sleep(0.3)
    
    out = h1.cmd("timeout 1 iperf -c 10.0.0.3 -p 8081 -t 1 2>&1 || true")
    blocked = ("connect failed" in out.lower() or "refused" in out.lower() or 
               "timed out" in out.lower() or "no route" in out.lower() or
               len(out.strip()) < 20 or out.strip() == "")
    results.append(("IPv4 TCP h1→h3", blocked))
    info(f"Resultado: {'BLOCKED' if blocked else 'ALLOWED'}\n")
    
    h3.cmd("pkill -9 iperf || true")

    # TEST 3.3: IPv4 UDP h1→h3 con iperf (debe bloquearse)
    info("\n--- TEST 3.3: IPv4 UDP (iperf) h1 → h3 (debe bloquearse) ---\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -u -p 8081 > /tmp/iperf_udp_h3_8081.log 2>&1 &")
    time.sleep(0.5)
    
    out = h1.cmd("timeout 3 iperf -c 10.0.0.3 -u -p 8081 -t 1 -b 1M 2>&1 || true")
    server_log = h3.cmd("cat /tmp/iperf_udp_h3_8081.log 2>/dev/null || true")
    no_data = "Server listening" in server_log and "bits/sec" not in server_log
    blocked = no_data or len(out.strip()) < 50
    results.append(("IPv4 UDP h1→h3", blocked))
    info(f"Resultado: {'BLOCKED' if blocked else 'ALLOWED'}\n")
    
    h3.cmd("pkill -9 iperf || true")

    # TEST 3.4: IPv6 ping h1→h3 (debe bloquearse)
    info("\n--- TEST 3.4: IPv6 ping h1 → h3 (debe bloquearse) ---\n")
    out = h1.cmd("ping6 -c 3 fd00::3")
    m = re.search(r'(\d+)% packet loss', out)
    loss = int(m.group(1)) if m else None
    blocked = (loss == 100)
    results.append(("IPv6 ping h1→h3", blocked))
    info(f"Resultado: {'BLOCKED' if blocked else 'ALLOWED'} (loss={loss}%)\n")

    # TEST 3.5: IPv6 TCP h1→h3 con iperf (debe bloquearse)
    info("\n--- TEST 3.5: IPv6 TCP (iperf) h1 → h3 (debe bloquearse) ---\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -V -p 8082 > /tmp/iperf_v6_h3_8082.log 2>&1 &")
    time.sleep(0.3)
    
    out = h1.cmd("timeout 1 iperf -c fd00::3 -V -p 8082 -t 1 2>&1 || true")
    blocked = ("connect failed" in out.lower() or "refused" in out.lower() or 
               "timed out" in out.lower() or "no route" in out.lower() or
               len(out.strip()) < 20 or out.strip() == "")
    results.append(("IPv6 TCP h1→h3", blocked))
    info(f"Resultado: {'BLOCKED' if blocked else 'ALLOWED'}\n")
    
    h3.cmd("pkill -9 iperf || true")

    # TEST 3.6: IPv6 UDP h1→h3 con iperf (debe bloquearse)
    info("\n--- TEST 3.6: IPv6 UDP (iperf) h1 → h3 (debe bloquearse) ---\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -u -V -p 8082 > /tmp/iperf_udp_v6_h3_8082.log 2>&1 &")
    time.sleep(0.5)
    
    out = h1.cmd("timeout 3 iperf -c fd00::3 -u -V -p 8082 -t 1 -b 1M 2>&1 || true")
    server_log = h3.cmd("cat /tmp/iperf_udp_v6_h3_8082.log 2>/dev/null || true")
    no_data = "Server listening" in server_log and "bits/sec" not in server_log
    blocked = no_data or len(out.strip()) < 50
    results.append(("IPv6 UDP h1→h3", blocked))
    info(f"Resultado: {'BLOCKED' if blocked else 'ALLOWED'}\n")
    
    h3.cmd("pkill -9 iperf || true")

    # ========================================
    # CASOS DE ÉXITO (NO debe bloquear)
    # ========================================
    info("\n" + "="*60 + "\n")
    info("   CASOS DE ÉXITO (NO debe bloquear)\n")
    info("="*60 + "\n")

    # TEST 3.7: IPv4 ping h1→h2 (permitido)
    info("\n--- TEST 3.7: h1 → h2 IPv4 ping (permitido) ---\n")
    out = h1.cmd("ping -c2 10.0.0.2")
    m = re.search(r'(\d+)% packet loss', out)
    loss = int(m.group(1)) if m else 100
    allowed = (loss < 100)
    results.append(("IPv4 ICMP h1→h2", allowed))
    info(f"Resultado: {'ALLOWED' if allowed else 'BLOCKED'}\n")

    # TEST 3.8: IPv6 ping h1→h2 (permitido)
    info("\n--- TEST 3.8: h1 → h2 IPv6 ping (permitido) ---\n")
    out = h1.cmd("ping6 -c2 fd00::2")
    m = re.search(r'(\d+)% packet loss', out)
    loss = int(m.group(1)) if m else 100
    allowed = (loss < 100)
    results.append(("IPv6 ICMP h1→h2", allowed))
    info(f"Resultado: {'ALLOWED' if allowed else 'BLOCKED'}\n")

    # TEST 3.9: IPv4 TCP h3→h4 con iperf (permitido)
    info("\n--- TEST 3.9: h3 → h4 TCP (iperf, permitido) ---\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -p 9000 > /tmp/iperf_h4_9000.log 2>&1 &")
    time.sleep(0.5)
    
    out = h3.cmd("timeout 3 iperf -c 10.0.0.4 -p 9000 -t 1 2>&1 || true")
    allowed = "bits/sec" in out
    results.append(("IPv4 TCP h3→h4", allowed))
    info(f"Resultado: {'ALLOWED' if allowed else 'BLOCKED'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # TEST 3.10: IPv6 TCP h3→h4 con iperf (permitido)
    info("\n--- TEST 3.10: h3 → h4 IPv6 TCP (iperf, permitido) ---\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -V -p 9001 > /tmp/iperf_v6_h4_9001.log 2>&1 &")
    time.sleep(0.5)
    
    out = h3.cmd("timeout 3 iperf -c fd00::4 -V -p 9001 -t 1 2>&1 || true")
    allowed = "bits/sec" in out
    results.append(("IPv6 TCP h3→h4", allowed))
    info(f"Resultado: {'ALLOWED' if allowed else 'BLOCKED'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # TEST 3.11: IPv4 UDP h2→h4 con iperf (permitido)
    info("\n--- TEST 3.11: h2 → h4 UDP (iperf, permitido) ---\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -u -p 9000 > /tmp/iperf_udp_h4_9000.log 2>&1 &")
    time.sleep(0.5)
    
    out = h2.cmd("timeout 3 iperf -c 10.0.0.4 -u -p 9000 -t 1 -b 1M 2>&1 || true")
    allowed = "bits/sec" in out
    results.append(("IPv4 UDP h2→h4", allowed))
    info(f"Resultado: {'ALLOWED' if allowed else 'BLOCKED'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # TEST 3.12: IPv6 UDP h2→h4 con iperf (permitido)
    info("\n--- TEST 3.12: h2 → h4 IPv6 UDP (iperf, permitido) ---\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -u -V -p 9001 > /tmp/iperf_udp_v6_h4_9001.log 2>&1 &")
    time.sleep(0.5)
    
    out = h2.cmd("timeout 3 iperf -c fd00::4 -u -V -p 9001 -t 1 -b 1M 2>&1 || true")
    allowed = "bits/sec" in out
    results.append(("IPv6 UDP h2→h4", allowed))
    info(f"Resultado: {'ALLOWED' if allowed else 'BLOCKED'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # ========================================
    # RESUMEN FINAL
    # ========================================
    info("\n" + "="*60 + "\n")
    info("                RESULTADOS REGLA 3\n")
    info("="*60 + "\n")
    
    passed = sum(1 for _, ok in results if ok)
    
    for test_name, ok in results:
        symbol = "✓" if ok else "✗"
        info(f"  {symbol} {test_name:20s} → {'OK' if ok else 'FAIL'}\n")
    
    info("\n" + "-"*60 + "\n")
    info(f"  Tests pasados: {passed}/{len(results)}\n")
    info(f"  Tests fallidos: {len(results) - passed}/{len(results)}\n")
    info("="*60 + "\n")

    # Cleanup
    for h in [h1, h2, h3, h4]:
        h.cmd("pkill -9 iperf || true")
    
    net.stop()
    info("\n*** Tests completados ***\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 test_regla3_iperf.py <num_switches>")
        sys.exit(1)
    
    n = int(sys.argv[1])
    if n < 2:
        print("La topología requiere al menos 2 switches")
        sys.exit(1)

    run_tests(n)
