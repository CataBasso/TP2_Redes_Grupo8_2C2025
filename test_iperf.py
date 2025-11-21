#!/usr/bin/env python3
"""
TEST COMPLETO: Validación de Firewall con Iperf.
Este script prueba las 3 reglas secuencialmente.
"""
import sys
import time
import re
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from topologia import ChainTopo

# Códigos de color ANSI para la terminal
class BColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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
    info(f"\n{BColors.HEADER}===== REGLA 1: PUERTO 80 - BLOQUEADO) ====={BColors.ENDC}\n")

    # 1.1 TCP
    info("Test 1.1: TCP Puerto 80 (Debe BLOQUEARSE)... ")
    h3.cmd("iperf -s -p 80 > /dev/null 2>&1 &")
    time.sleep(0.5)
    out = h2.cmd("timeout 2 iperf -c 10.0.0.3 -p 80 -t 1")
    blocked = "connect failed" in out or "refused" in out or len(out.strip()) == 0
    
    if blocked:
        info(f"{BColors.OKGREEN}✓ BLOQUEADO{BColors.ENDC}\n")
    else:
        info(f"{BColors.FAIL}✗ PERMITIDO{BColors.ENDC}\n")
    results.append(("R1 TCP", blocked))
    h3.cmd("pkill -9 iperf")

    # 1.2 UDP
    info("Test 1.2: UDP Puerto 80 (Debe BLOQUEARSE)... ")
    h3.cmd("iperf -s -u -p 80 > /tmp/r1_udp4.log 2>&1 &")
    time.sleep(0.5)
    h2.cmd("timeout 2 iperf -c 10.0.0.3 -u -p 80 -t 1 -b 1M")
    log = h3.cmd("cat /tmp/r1_udp4.log")
    blocked = "bits/sec" not in log
    
    if blocked:
        info(f"{BColors.OKGREEN}✓ BLOQUEADO{BColors.ENDC}\n")
    else:
        info(f"{BColors.FAIL}✗ PERMITIDO{BColors.ENDC}\n")
    results.append(("R1 UDP", blocked))
    h3.cmd("pkill -9 iperf")

    # 1.3 Caso permitido TCP
    info("Test 1.3: TCP Puerto 8080 (Debe PERMITIRSE)... ")
    h3.cmd("iperf -s -p 8080 > /dev/null 2>&1 &")
    time.sleep(0.5)
    out = h2.cmd("timeout 2 iperf -c 10.0.0.3 -p 8080 -t 1")
    allowed = "bits/sec" in out
    
    if allowed:
        info(f"{BColors.OKGREEN}✓ PERMITIDO{BColors.ENDC}\n")
    else:
        info(f"{BColors.FAIL}✗ BLOQUEADO{BColors.ENDC}\n")
    results.append(("R1 TCP 8080", allowed))
    h3.cmd("pkill -9 iperf")

    # 1.4 Caso permitido UDP
    info("Test 1.4: UDP Puerto 8080 (Debe PERMITIRSE)... ")
    h3.cmd("iperf -s -u -p 8080 > /tmp/r1_udp_ok.log 2>&1 &")
    time.sleep(0.5)
    h2.cmd("timeout 2 iperf -c 10.0.0.3 -u -p 8080 -t 1 -b 1M")
    
    log = h3.cmd("cat /tmp/r1_udp_ok.log")
    allowed = "bits/sec" in log
    
    if allowed: info(f"{BColors.OKGREEN}✓ PERMITIDO{BColors.ENDC}\n")
    else: info(f"{BColors.FAIL}✗ BLOQUEADO{BColors.ENDC}\n")
    results.append(("R1 UDP 8080", allowed))
    h3.cmd("pkill -9 iperf")

    # ============================================================
    # PARTE 2: REGLA 2 (UDP 5001)
    # ============================================================
    info(f"\n{BColors.HEADER}===== REGLA 2: h1 → 5001 CON UDP - BLOQUEADO) ====={BColors.ENDC}\n")

    # 2.1 UDP 
    info("Test 2.1: UDP 5001 (Debe BLOQUEARSE)... ")
    h4.cmd("iperf -s -u -p 5001 > /tmp/r2_udp4.log 2>&1 &")
    time.sleep(0.5)
    h1.cmd("timeout 2 iperf -c 10.0.0.4 -u -p 5001 -t 1 -b 1M")
    log = h4.cmd("cat /tmp/r2_udp4.log")
    blocked = "bits/sec" not in log
    
    if blocked:
        info(f"{BColors.OKGREEN}✓ BLOQUEADO{BColors.ENDC}\n")
    else:
        info(f"{BColors.FAIL}✗ PERMITIDO{BColors.ENDC}\n")
    results.append(("R2 UDP", blocked))
    h4.cmd("pkill -9 iperf")

    # 2.2 Caso permitido TCP
    info("Test 2.2: TCP 5001 (Debe PERMITIRSE)... ")
    h4.cmd("iperf -s -p 5001 > /dev/null 2>&1 &")
    time.sleep(0.5)
    out = h1.cmd("timeout 2 iperf -c 10.0.0.4 -p 5001 -t 1")
    allowed = "bits/sec" in out
    
    if allowed:
        info(f"{BColors.OKGREEN}✓ PERMITIDO{BColors.ENDC}\n")
    else:
        info(f"{BColors.FAIL}✗ BLOQUEADO{BColors.ENDC}\n")
    results.append(("R2 TCP", allowed))
    h4.cmd("pkill -9 iperf")

    # ============================================================
    # PARTE 3: REGLA 3 (h1 <-> h3)
    # ============================================================
    info(f"\n{BColors.HEADER}===== REGLA 3: h1 ↔ h3 - BLOQUEADO) ====={BColors.ENDC}\n")

    # 3.1 Ping
    info("Test 3.1: Ping (Debe BLOQUEARSE)... ")
    out = h1.cmd("ping -c 2 -W 1 10.0.0.3")
    blocked = "100% packet loss" in out
    
    if blocked:
        info(f"{BColors.OKGREEN}✓ BLOQUEADO{BColors.ENDC}\n")
    else:
        info(f"{BColors.FAIL}✗ PERMITIDO{BColors.ENDC}\n")
    results.append(("R3 Ping", blocked))

    # 3.2 TCP
    info("Test 3.2: TCP (Debe BLOQUEARSE)... ")
    h3.cmd("iperf -s -p 9000 > /dev/null 2>&1 &")
    time.sleep(0.5)
    out = h1.cmd("timeout 2 iperf -c 10.0.0.3 -p 9000 -t 1")
    blocked = "connect failed" in out or "refused" in out or len(out.strip()) == 0
    
    if blocked:
        info(f"{BColors.OKGREEN}✓ BLOQUEADO{BColors.ENDC}\n")
    else:
        info(f"{BColors.FAIL}✗ PERMITIDO{BColors.ENDC}\n")
    results.append(("R3 TCP", blocked))
    h3.cmd("pkill -9 iperf")

    # 3.3 UDP (Debe fallar)
    info("Test 3.3: UDP (Debe BLOQUEARSE)... ")
    h3.cmd("iperf -s -u -p 9000 > /tmp/r3_udp.log 2>&1 &")
    time.sleep(0.5)
    h1.cmd("timeout 2 iperf -c 10.0.0.3 -u -p 9000 -t 1 -b 1M")
    log = h3.cmd("cat /tmp/r3_udp.log")
    blocked = "bits/sec" not in log
    
    if blocked: info(f"{BColors.OKGREEN}✓ BLOQUEADO{BColors.ENDC}\n")
    else: info(f"{BColors.FAIL}✗ PERMITIDO{BColors.ENDC}\n")
    results.append(("R3 UDP", blocked))
    h3.cmd("pkill -9 iperf")

    # ========================================
    # RESUMEN FINAL
    # ========================================
    info(f"\n{BColors.HEADER}========== REPORTE FINAL DE EJECUCIÓN =========={BColors.ENDC}\n")
    
    passed = 0
    for test_name, ok in results:
        status = f"{BColors.OKGREEN}[ PASS ]{BColors.ENDC}" if ok else f"{BColors.FAIL}[ FAIL ]{BColors.ENDC}"
        passed += 1 if ok else 0
        print(f" {test_name:.<45} {status}")
    
    print("-" * 60)
    print(f" Total: {len(results)} | Pasados: {BColors.OKGREEN}{passed}{BColors.ENDC} | Fallados: {BColors.FAIL}{len(results)-passed}{BColors.ENDC}")
    print("-" * 60)

    if passed == len(results):
        print(f"\n{BColors.OKGREEN}{BColors.BOLD}>>> TODO OK (SUCCESS) <<<{BColors.ENDC}\n")
    else:
        print(f"\n{BColors.FAIL}{BColors.BOLD}>>> ERRORES DETECTADOS <<<{BColors.ENDC}\n")

    # Cleanup
    for h in [h1, h2, h3, h4]:
        h.cmd("pkill -9 iperf || true")
    
    net.stop()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 test_iperf.py <num_switches>")
        sys.exit(1)
    
    n = int(sys.argv[1])
    if n < 2:
        print("La topología requiere al menos 2 switches")
        sys.exit(1)

    run_consolidated_tests(n)