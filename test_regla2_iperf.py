#!/usr/bin/env python3
"""
Test de Regla 2 con iperf: Bloquear h1 → puerto 5001 UDP
Replica exactamente test_regla2.py pero con iperf
"""
import sys
import time
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
    info("Forzando aprendizaje de MACs...\n")
    h1.cmd('ping -c 1 10.0.0.3 > /dev/null 2>&1 || true')
    time.sleep(0.5)

    results = []

    info("\n" + "="*60 + "\n")
    info("   TEST REGLA 2 - h1 → 5001 UDP BLOQUEADO (IPERF)\n")
    info("="*60 + "\n")

    # TEST 2.1: IPv4 UDP h1→h4:5001 (debe bloquearse)
    info("\nTEST 2.1: IPv4 + UDP h1→h4:5001 (debe BLOQUEARSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -u -p 5001 > /tmp/iperf_5001_udp_v4.log 2>&1 &")
    time.sleep(0.3)
    
    output = h1.cmd("timeout 3 iperf -c 10.0.0.4 -u -p 5001 -t 1 -b 1M 2>&1 || true")
    server_log = h4.cmd("cat /tmp/iperf_5001_udp_v4.log 2>/dev/null || true")
    no_data = "Server listening" in server_log and "bits/sec" not in server_log
    blocked = no_data or len(output.strip()) < 50
    results.append(("IPv4 UDP", blocked))
    info(f"Resultado: {'BLOQUEADO' if blocked else 'PERMITIDO'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # TEST 2.2: IPv6 UDP h1→h4:5001 (debe bloquearse)
    info("\nTEST 2.2: IPv6 + UDP h1→h4:5001 (debe BLOQUEARSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -u -V -p 5001 > /tmp/iperf_5001_udp_v6.log 2>&1 &")
    time.sleep(0.3)
    
    output = h1.cmd("timeout 3 iperf -c fd00::4 -u -V -p 5001 -t 1 -b 1M 2>&1 || true")
    server_log = h4.cmd("cat /tmp/iperf_5001_udp_v6.log 2>/dev/null || true")
    no_data = "Server listening" in server_log and "bits/sec" not in server_log
    blocked = no_data or len(output.strip()) < 50
    results.append(("IPv6 UDP", blocked))
    info(f"Resultado: {'BLOQUEADO' if blocked else 'PERMITIDO'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # ========================================
    # CASOS DE ÉXITO
    # ========================================
    info("\n" + "-"*60 + "\n")
    info("   CASOS DE ÉXITO\n")
    info("-"*60 + "\n")

    # TEST 2.3: IPv4 TCP h1→h4:5001 (debe permitirse)
    info("\nTEST 2.3: IPv4 + TCP h1→h4:5001 (debe PERMITIRSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -p 5001 > /tmp/iperf_5001_tcp_v4.log 2>&1 &")
    time.sleep(0.4)
    
    output = h1.cmd("timeout 3 iperf -c 10.0.0.4 -p 5001 -t 1 2>&1 || true")
    allowed = "bits/sec" in output
    results.append(("IPv4 TCP", allowed))
    info(f"Resultado: {'PERMITIDO' if allowed else 'BLOQUEADO'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # TEST 2.4: IPv6 TCP h1→h4:5001 (debe permitirse)
    info("\nTEST 2.4: IPv6 + TCP h1→h4:5001 (debe PERMITIRSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -V -p 5001 > /tmp/iperf_5001_tcp_v6.log 2>&1 &")
    time.sleep(0.4)
    
    output = h1.cmd("timeout 3 iperf -c fd00::4 -V -p 5001 -t 1 2>&1 || true")
    allowed = "bits/sec" in output
    results.append(("IPv6 TCP", allowed))
    info(f"Resultado: {'PERMITIDO' if allowed else 'BLOQUEADO'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # ========================================
    # RESUMEN FINAL
    # ========================================
    info("\n" + "="*60 + "\n")
    info("                RESULTADOS REGLA 2\n")
    info("="*60 + "\n")
    
    passed = sum(1 for _, ok in results if ok)
    
    for test_name, ok in results:
        symbol = "✓" if ok else "✗"
        info(f"  {symbol} {test_name:12s} → {'OK' if ok else 'FAIL'}\n")
    
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
        print("Uso: sudo python3 test_regla2_iperf.py <num_switches>")
        sys.exit(1)
    
    n = int(sys.argv[1])
    if n < 2:
        print("La topología requiere al menos 2 switches")
        sys.exit(1)

    run_tests(n)
