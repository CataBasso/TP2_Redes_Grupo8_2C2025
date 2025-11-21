#!/usr/bin/env python3
"""
TEST DEFINITIVO: Validación de Firewall con Iperf.
Este script prueba las 3 reglas secuencialmente, evitando conflictos de topología.
"""
import sys
import time
import re
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from topologia import ChainTopo

def run_consolidated_tests(n):
    setLogLevel('info')
    topo = ChainTopo(n=int(n))
    c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch)
    net.addController(c0)

    info("\n=== Iniciando Mininet ===\n")
    net.start()
    time.sleep(2)

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    # Configuración IPv6
    for i, h in enumerate([h1, h2, h3, h4], start=1):
        h.cmd(f"ip -6 addr add fd00::{i}/64 dev {h.name}-eth0 || true")

    # Warm-up
    info("Forzando aprendizaje de MACs...\n")
    for h in [h1, h2, h3, h4]:
        h.cmd('ping -c 1 10.0.0.1 > /dev/null 2>&1 || true')
        h.cmd('ping -c 1 10.0.0.4 > /dev/null 2>&1 || true')
    time.sleep(1)

    results = []

    # ============================================================
    # PARTE 1: REGLA 1 (Puerto 80)
    # ============================================================
    info("\n" + "="*60 + "\n")
    info("   REGLA 1: Puerto 80 BLOQUEADO (h2->h3)\n")
    info("="*60 + "\n")

    # Test 1.1: TCP puerto 80 (bloqueado)
    info("\nTest 1.1: h2 → h3:80 TCP (debe BLOQUEARSE)\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -p 80 > /tmp/iperf_80_server.log 2>&1 &")
    time.sleep(0.5)
    
    output = h2.cmd("timeout 4 iperf -c 10.0.0.3 -p 80 -t 2 2>&1 || true")
    blocked = "connect failed" in output.lower() or "connection refused" in output.lower() or len(output.strip()) == 0
    results.append(("R1: TCP Port 80", blocked))
    info(f"Resultado: {'✓ BLOQUEADO' if blocked else '✗ PERMITIDO'}\n")
    h3.cmd("pkill -9 iperf || true")

    # Test 1.2: Puerto 8000 TCP (permitido)
    info("\nTest 1.2: h2 → h3:8000 TCP (debe PERMITIRSE)\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -p 8000 > /tmp/iperf_8000_server.log 2>&1 &")
    time.sleep(0.5)
    
    output = h2.cmd("timeout 4 iperf -c 10.0.0.3 -p 8000 -t 2 2>&1 || true")
    allowed = "bits/sec" in output or "Mbits/sec" in output
    results.append(("R1: TCP Port 8000 Allowed", allowed))
    info(f"Resultado: {'✓ PERMITIDO' if allowed else '✗ BLOQUEADO'}\n")
    h3.cmd("pkill -9 iperf || true")

    # ============================================================
    # PARTE 2: REGLA 2 (UDP 5001)
    # Estrategia: h1 -> h4
    # ============================================================
    info("\n" + "="*60 + "\n")
    info("   REGLA 2: h1 → 5001 UDP BLOQUEADO\n")
    info("="*60 + "\n")

    # TEST 2.1: IPv4 UDP h1→h4:5001 (debe bloquearse)
    info("\nTest 2.1: IPv4 + UDP h1→h4:5001 (debe BLOQUEARSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -u -p 5001 > /tmp/iperf_5001_udp_v4.log 2>&1 &")
    time.sleep(0.5) # Espera clave para que levante el server
    
    output = h1.cmd("timeout 3 iperf -c 10.0.0.4 -u -p 5001 -t 1 -b 1M 2>&1 || true")
    server_log = h4.cmd("cat /tmp/iperf_5001_udp_v4.log 2>/dev/null || true")
    no_data = "bits/sec" not in server_log
    results.append(("R2: IPv4 UDP 5001", no_data))
    info(f"Resultado: {'✓ BLOQUEADO' if no_data else '✗ PERMITIDO'}\n")
    h4.cmd("pkill -9 iperf || true")

    # TEST 2.2: IPv6 UDP h1→h4:5001 (debe bloquearse)
    info("\nTest 2.2: IPv6 + UDP h1→h4:5001 (debe BLOQUEARSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -u -V -p 5001 > /tmp/iperf_5001_udp_v6.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 3 iperf -c fd00::4 -u -V -p 5001 -t 1 -b 1M 2>&1 || true")
    server_log = h4.cmd("cat /tmp/iperf_5001_udp_v6.log 2>/dev/null || true")
    no_data = "bits/sec" not in server_log
    results.append(("R2: IPv6 UDP 5001", no_data))
    info(f"Resultado: {'✓ BLOQUEADO' if no_data else '✗ PERMITIDO'}\n")
    h4.cmd("pkill -9 iperf || true")

    # TEST 2.3: IPv4 TCP h1→h4:5001 (debe permitirse)
    info("\nTest 2.3: IPv4 + TCP h1→h4:5001 (debe PERMITIRSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.5)
    h4.cmd("iperf -s -p 5001 > /tmp/iperf_5001_tcp_v4.log 2>&1 &")
    time.sleep(1)
    
    output = h1.cmd("timeout 5 iperf -c 10.0.0.4 -p 5001 -t 1 2>&1 || true")
    allowed = "bits/sec" in output or "Mbits/sec" in output
    results.append(("R2: IPv4 TCP 5001 Allowed", allowed))
    info(f"Resultado: {'✓ PERMITIDO' if allowed else '✗ BLOQUEADO'}\n")
    h4.cmd("pkill -9 iperf || true")

    # ============================================================
    # PARTE 3: REGLA 3 (h1 <-> h3)
    # ============================================================
    info("\n" + "="*60 + "\n")
    info("   REGLA 3: Bloqueo h1 ↔ h3\n")
    info("="*60 + "\n")

    # TEST 3.1: IPv4 ping h1→h3 (debe bloquearse)
    info("\nTest 3.1: IPv4 ping h1 → h3 (debe BLOQUEARSE)\n")
    out = h1.cmd("ping -c 3 10.0.0.3")
    m = re.search(r'(\d+)% packet loss', out)
    loss = int(m.group(1)) if m else None
    blocked = (loss == 100)
    results.append(("R3: IPv4 ping h1->h3", blocked))
    info(f"Resultado: {'✓ BLOQUEADO' if blocked else '✗ PERMITIDO'} (loss={loss}%)\n")

    # TEST 3.2: IPv4 TCP h1→h3 con iperf (debe bloquearse)
    info("\nTest 3.2: IPv4 TCP (iperf) h1 → h3 (debe BLOQUEARSE)\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -p 8081 > /tmp/iperf_h3_8081.log 2>&1 &")
    time.sleep(0.5)
    out = h1.cmd("timeout 2 iperf -c 10.0.0.3 -p 8081 -t 1 2>&1 || true")
    blocked = "connect failed" in out.lower() or "connection refused" in out.lower() or len(out.strip()) == 0
    results.append(("R3: IPv4 TCP h1->h3", blocked))
    info(f"Resultado: {'✓ BLOQUEADO' if blocked else '✗ PERMITIDO'}\n")
    h3.cmd("pkill -9 iperf || true")

    # ========================================
    # RESUMEN FINAL
    # ========================================
    info("\n" + "="*60 + "\n")
    info("                RESUMEN FINAL\n")
    info("="*60 + "\n")
    
    passed = 0
    for test_name, ok in results:
        symbol = "✓" if ok else "✗"
        status_text = "PASSED" if ok else "FAILED"
        info(f"  {symbol} {test_name:30s} → {status_text}\n")
        if ok:
            passed += 1
    
    info("\n" + "-"*60 + "\n")
    info(f"  Total Tests: {len(results)}\n")
    info(f"  Pasados:     {passed}\n")
    info(f"  Fallados:    {len(results) - passed}\n")
    info("="*60 + "\n")

    # Cleanup
    for h in [h1, h2, h3, h4]:
        h.cmd("pkill -9 iperf || true")
    
    net.stop()
    info("\n*** Tests completados ***\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 test_definitivo.py <num_switches>")
        sys.exit(1)
    
    n = int(sys.argv[1])
    if n < 2:
        print("La topología requiere al menos 2 switches")
        sys.exit(1)

    run_consolidated_tests(n)