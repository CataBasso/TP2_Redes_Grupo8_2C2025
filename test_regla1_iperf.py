#!/usr/bin/env python3
"""
Test de Regla 1 con iperf: Bloquear puerto 80
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
    h1.cmd('ping -c 1 10.0.0.2 > /dev/null 2>&1 || true')
    h2.cmd('ping -c 1 10.0.0.3 > /dev/null 2>&1 || true')
    h3.cmd('ping -c 1 10.0.0.4 > /dev/null 2>&1 || true')
    h4.cmd('ping -c 1 10.0.0.1 > /dev/null 2>&1 || true')
    time.sleep(0.8)

    results = []

    info("\n" + "="*60 + "\n")
    info("   TEST REGLA 1 - PUERTO 80 BLOQUEADO (IPERF)\n")
    info("="*60 + "\n")

    # TEST 1.1: IPv4 TCP puerto 80 (debe bloquearse)
    info("\nTEST 1.1: IPv4 + TCP h1→h3:80 (debe BLOQUEARSE)\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -p 80 > /tmp/iperf_80_v4.log 2>&1 &")
    time.sleep(0.3)
    
    output = h1.cmd("timeout 1 iperf -c 10.0.0.3 -p 80 -t 1 2>&1 || true")
    blocked = ("connect failed" in output.lower() or "refused" in output.lower() or 
               "timed out" in output.lower() or "no route" in output.lower() or
               len(output.strip()) < 20 or output.strip() == "")
    results.append(("IPv4 TCP", blocked))
    info(f"Resultado: {'BLOQUEADO' if blocked else 'PERMITIDO'}\n")
    
    h3.cmd("pkill -9 iperf || true")

    # TEST 1.2: IPv4 UDP puerto 80 (debe bloquearse)
    info("\nTEST 1.2: IPv4 + UDP h1→h3:80 (debe BLOQUEARSE)\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -u -p 80 > /tmp/iperf_80_udp_v4.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 3 iperf -c 10.0.0.3 -u -p 80 -t 1 -b 1M 2>&1 || true")
    server_log = h3.cmd("cat /tmp/iperf_80_udp_v4.log 2>/dev/null || true")
    no_data = "Server listening" in server_log and "bits/sec" not in server_log
    blocked = no_data or len(output.strip()) < 50
    results.append(("IPv4 UDP", blocked))
    info(f"Resultado: {'BLOQUEADO' if blocked else 'PERMITIDO'}\n")
    
    h3.cmd("pkill -9 iperf || true")

    # TEST 1.3: IPv6 TCP puerto 80 (debe bloquearse)
    info("\nTEST 1.3: IPv6 + TCP h1→h3:80 (debe BLOQUEARSE)\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -V -p 80 > /tmp/iperf_80_v6.log 2>&1 &")
    time.sleep(0.3)
    
    output = h1.cmd("timeout 1 iperf -c fd00::3 -V -p 80 -t 1 2>&1 || true")
    blocked = ("connect failed" in output.lower() or "refused" in output.lower() or 
               "timed out" in output.lower() or "no route" in output.lower() or
               len(output.strip()) < 20 or output.strip() == "")
    results.append(("IPv6 TCP", blocked))
    info(f"Resultado: {'BLOQUEADO' if blocked else 'PERMITIDO'}\n")
    
    h3.cmd("pkill -9 iperf || true")

    # TEST 1.4: IPv6 UDP puerto 80 (debe bloquearse)
    info("\nTEST 1.4: IPv6 + UDP h1→h3:80 (debe BLOQUEARSE)\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -u -V -p 80 > /tmp/iperf_80_udp_v6.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 3 iperf -c fd00::3 -u -V -p 80 -t 1 -b 1M 2>&1 || true")
    server_log = h3.cmd("cat /tmp/iperf_80_udp_v6.log 2>/dev/null || true")
    no_data = "Server listening" in server_log and "bits/sec" not in server_log
    blocked = no_data or len(output.strip()) < 50
    results.append(("IPv6 UDP", blocked))
    info(f"Resultado: {'BLOQUEADO' if blocked else 'PERMITIDO'}\n")
    
    h3.cmd("pkill -9 iperf || true")

    # ========================================
    # CASOS DE ÉXITO (puertos permitidos)
    # ========================================
    info("\n" + "-"*60 + "\n")
    info("   CASOS DE ÉXITO — PUERTOS PERMITIDOS\n")
    info("-"*60 + "\n")

    # TEST 1.5: IPv4 TCP puerto 8080 (debe permitirse)
    info("\nTEST 1.5: IPv4 + TCP h1→h4:8080 (debe PERMITIRSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -p 8080 > /tmp/iperf_8080_v4.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 3 iperf -c 10.0.0.4 -p 8080 -t 1 2>&1 || true")
    allowed = "bits/sec" in output
    results.append(("IPv4 TCP OK (8080)", allowed))
    info(f"Resultado: {'PERMITIDO' if allowed else 'BLOQUEADO'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # TEST 1.6: IPv4 UDP puerto 8080 (debe permitirse)
    info("\nTEST 1.6: IPv4 + UDP h1→h4:8080 (debe PERMITIRSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -u -p 8080 > /tmp/iperf_8080_udp_v4.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 3 iperf -c 10.0.0.4 -u -p 8080 -t 1 -b 1M 2>&1 || true")
    allowed = "bits/sec" in output
    results.append(("IPv4 UDP OK (8080)", allowed))
    info(f"Resultado: {'PERMITIDO' if allowed else 'BLOQUEADO'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # TEST 1.7: IPv6 TCP puerto 8080 (debe permitirse)
    info("\nTEST 1.7: IPv6 + TCP h1→h4:8080 (debe PERMITIRSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -V -p 8080 > /tmp/iperf_8080_v6.log 2>&1 &")
    time.sleep(0.7)
    
    output = h1.cmd("timeout 3 iperf -c fd00::4 -V -p 8080 -t 1 2>&1 || true")
    allowed = "bits/sec" in output
    results.append(("IPv6 TCP OK (8080)", allowed))
    info(f"Resultado: {'PERMITIDO' if allowed else 'BLOQUEADO'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # TEST 1.8: IPv6 UDP puerto 8080 (debe permitirse)
    info("\nTEST 1.8: IPv6 + UDP h1→h4:8080 (debe PERMITIRSE)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -u -V -p 8080 > /tmp/iperf_8080_udp_v6.log 2>&1 &")
    time.sleep(0.7)
    
    output = h1.cmd("timeout 3 iperf -c fd00::4 -u -V -p 8080 -t 1 -b 1M 2>&1 || true")
    allowed = "bits/sec" in output
    results.append(("IPv6 UDP OK (8080)", allowed))
    info(f"Resultado: {'PERMITIDO' if allowed else 'BLOQUEADO'}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # ========================================
    # RESUMEN FINAL
    # ========================================
    info("\n" + "="*60 + "\n")
    info("                RESULTADOS REGLA 1\n")
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
        print("Uso: sudo python3 test_regla1_iperf.py <num_switches>")
        sys.exit(1)
    
    n = int(sys.argv[1])
    if n < 2:
        print("La topología requiere al menos 2 switches")
        sys.exit(1)

    run_tests(n)
