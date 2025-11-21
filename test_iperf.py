"""
Script para probar las reglas del firewall usando iperf
según lo solicitado en el TP.
"""
import sys
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from topologia import ChainTopo


def run_iperf_tests(n):
    setLogLevel('info')
    topo = ChainTopo(n=int(n))
    c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch)
    net.addController(c0)

    info("\n=== Iniciando Mininet ===\n")
    net.start()
    time.sleep(1)

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    # Warm-up: forzar aprendizaje de MACs
    info("Forzando aprendizaje de MACs...\n")
    h1.cmd('ping -c 1 10.0.0.2 > /dev/null 2>&1 || true')
    h2.cmd('ping -c 1 10.0.0.3 > /dev/null 2>&1 || true')
    h3.cmd('ping -c 1 10.0.0.4 > /dev/null 2>&1 || true')
    h4.cmd('ping -c 1 10.0.0.1 > /dev/null 2>&1 || true')
    time.sleep(1)

    results = []

    info("\n" + "="*60 + "\n")
    info("   PRUEBAS DE FIREWALL CON IPERF\n")
    info("="*60 + "\n")

    # ========================================
    # REGLA 1: Bloqueo de puerto 80
    # ========================================
    info("\n" + "-"*60 + "\n")
    info("REGLA 1: Puerto destino 80 debe estar BLOQUEADO\n")
    info("-"*60 + "\n")

    # Test 1.1: TCP puerto 80 (bloqueado)
    info("\nTest 1.1: h1 → h2:80 TCP (debe fallar)\n")
    h2.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h2.cmd("iperf -s -p 80 > /tmp/iperf_80_server.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 5 iperf -c 10.0.0.2 -p 80 -t 2 2>&1 || true")
    
    # Si iperf falla o no hay transferencia, está bloqueado
    blocked = "connect failed" in output.lower() or "connection refused" in output.lower() or len(output.strip()) == 0
    results.append(("Puerto 80 TCP", "BLOQUEADO" if blocked else "PERMITIDO", blocked))
    
    info(f"  Resultado: {'✓ BLOQUEADO (correcto)' if blocked else '✗ PERMITIDO (error)'}\n")
    if not blocked:
        info(f"  Output: {output[:200]}\n")
    
    h2.cmd("pkill -9 iperf || true")

    # Test 1.2: Puerto 8000 TCP (permitido - control)
    info("\nTest 1.2: h1 → h2:8000 TCP (debe funcionar)\n")
    h2.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h2.cmd("iperf -s -p 8000 > /tmp/iperf_8000_server.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 5 iperf -c 10.0.0.2 -p 8000 -t 2 2>&1 || true")
    
    allowed = "Mbits/sec" in output or "Kbits/sec" in output or "Gbits/sec" in output
    results.append(("Puerto 8000 TCP", "PERMITIDO" if allowed else "BLOQUEADO", allowed))
    
    info(f"  Resultado: {'✓ PERMITIDO (correcto)' if allowed else '✗ BLOQUEADO (error)'}\n")
    if allowed:
        # Extraer bandwidth
        for line in output.split('\n'):
            if 'Mbits/sec' in line or 'Kbits/sec' in line or 'Gbits/sec' in line:
                info(f"  Bandwidth: {line.strip()}\n")
                break
    
    h2.cmd("pkill -9 iperf || true")

    # ========================================
    # REGLA 2: h1 → puerto 5001 UDP bloqueado
    # ========================================
    info("\n" + "-"*60 + "\n")
    info("REGLA 2: h1 → puerto 5001 UDP debe estar BLOQUEADO\n")
    info("-"*60 + "\n")

    # Test 2.1: UDP puerto 5001 desde h1 (bloqueado)
    info("\nTest 2.1: h1 → h4:5001 UDP (debe fallar)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -u -p 5001 > /tmp/iperf_5001_udp_server.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 5 iperf -c 10.0.0.4 -u -p 5001 -t 2 -b 1M 2>&1 || true")
    
    # Para UDP, verificar si hay pérdida de paquetes del 100% o error de conexión
    blocked = "100%" in output or "connect" in output.lower() and "failed" in output.lower()
    
    # También verificar el log del servidor
    server_log = h4.cmd("cat /tmp/iperf_5001_udp_server.log 2>/dev/null || true")
    no_data_received = len(server_log.strip()) < 50 or "Server listening" in server_log and "Mbits/sec" not in server_log
    
    blocked = blocked or no_data_received
    results.append(("h1→5001 UDP", "BLOQUEADO" if blocked else "PERMITIDO", blocked))
    
    info(f"  Resultado: {'✓ BLOQUEADO (correcto)' if blocked else '✗ PERMITIDO (error)'}\n")
    if not blocked:
        info(f"  Output cliente: {output[:200]}\n")
        info(f"  Log servidor: {server_log[:200]}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # Test 2.2: UDP puerto 5001 desde h2 (permitido - control)
    info("\nTest 2.2: h2 → h4:5001 UDP (debe funcionar)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -u -p 5001 > /tmp/iperf_5001_udp_h2_server.log 2>&1 &")
    time.sleep(0.5)
    
    output = h2.cmd("timeout 5 iperf -c 10.0.0.4 -u -p 5001 -t 2 -b 1M 2>&1 || true")
    
    allowed = "Mbits/sec" in output or "Kbits/sec" in output
    results.append(("h2→5001 UDP", "PERMITIDO" if allowed else "BLOQUEADO", allowed))
    
    info(f"  Resultado: {'✓ PERMITIDO (correcto)' if allowed else '✗ BLOQUEADO (error)'}\n")
    if allowed:
        for line in output.split('\n'):
            if 'Mbits/sec' in line or 'Kbits/sec' in line:
                info(f"  Bandwidth: {line.strip()}\n")
                break
    
    h4.cmd("pkill -9 iperf || true")

    # Test 2.3: TCP puerto 5001 desde h1 (permitido - solo UDP está bloqueado)
    info("\nTest 2.3: h1 → h4:5001 TCP (debe funcionar - solo UDP bloqueado)\n")
    h4.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h4.cmd("iperf -s -p 5001 > /tmp/iperf_5001_tcp_server.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 5 iperf -c 10.0.0.4 -p 5001 -t 2 2>&1 || true")
    
    allowed = "Mbits/sec" in output or "Kbits/sec" in output or "Gbits/sec" in output
    results.append(("h1→5001 TCP", "PERMITIDO" if allowed else "BLOQUEADO", allowed))
    
    info(f"  Resultado: {'✓ PERMITIDO (correcto)' if allowed else '✗ BLOQUEADO (error)'}\n")
    if allowed:
        for line in output.split('\n'):
            if 'Mbits/sec' in line or 'Kbits/sec' in line or 'Gbits/sec' in line:
                info(f"  Bandwidth: {line.strip()}\n")
                break
    else:
        info(f"  Output: {output[:300]}\n")
    
    h4.cmd("pkill -9 iperf || true")

    # ========================================
    # REGLA 3: h1 <-> h3 bloqueados
    # ========================================
    info("\n" + "-"*60 + "\n")
    info("REGLA 3: Comunicación h1 <-> h3 debe estar BLOQUEADA\n")
    info("-"*60 + "\n")

    # Test 3.1: h1 → h3 TCP (bloqueado)
    info("\nTest 3.1: h1 → h3 TCP (debe fallar)\n")
    h3.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h3.cmd("iperf -s -p 5555 > /tmp/iperf_h3_server.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 5 iperf -c 10.0.0.3 -p 5555 -t 2 2>&1 || true")
    
    blocked = "connect failed" in output.lower() or "connection refused" in output.lower() or len(output.strip()) < 20
    results.append(("h1→h3 TCP", "BLOQUEADO" if blocked else "PERMITIDO", blocked))
    
    info(f"  Resultado: {'✓ BLOQUEADO (correcto)' if blocked else '✗ PERMITIDO (error)'}\n")
    
    h3.cmd("pkill -9 iperf || true")

    # Test 3.2: h3 → h1 TCP (bloqueado - bidireccional)
    info("\nTest 3.2: h3 → h1 TCP (debe fallar)\n")
    h1.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h1.cmd("iperf -s -p 5555 > /tmp/iperf_h1_server.log 2>&1 &")
    time.sleep(0.5)
    
    output = h3.cmd("timeout 5 iperf -c 10.0.0.1 -p 5555 -t 2 2>&1 || true")
    
    blocked = "connect failed" in output.lower() or "connection refused" in output.lower() or len(output.strip()) < 20
    results.append(("h3→h1 TCP", "BLOQUEADO" if blocked else "PERMITIDO", blocked))
    
    info(f"  Resultado: {'✓ BLOQUEADO (correcto)' if blocked else '✗ BLOQUEADO (error)'}\n")
    
    h1.cmd("pkill -9 iperf || true")

    # Test 3.3: h1 → h2 TCP (permitido - control)
    info("\nTest 3.3: h1 → h2 TCP (debe funcionar)\n")
    h2.cmd("pkill -9 iperf || true")
    time.sleep(0.2)
    h2.cmd("iperf -s -p 5555 > /tmp/iperf_h2_control.log 2>&1 &")
    time.sleep(0.5)
    
    output = h1.cmd("timeout 5 iperf -c 10.0.0.2 -p 5555 -t 2 2>&1 || true")
    
    allowed = "Mbits/sec" in output or "Kbits/sec" in output or "Gbits/sec" in output
    results.append(("h1→h2 TCP", "PERMITIDO" if allowed else "BLOQUEADO", allowed))
    
    info(f"  Resultado: {'✓ PERMITIDO (correcto)' if allowed else '✗ BLOQUEADO (error)'}\n")
    
    h2.cmd("pkill -9 iperf || true")

    # ========================================
    # RESUMEN FINAL
    # ========================================
    info("\n" + "="*60 + "\n")
    info("                RESUMEN DE RESULTADOS\n")
    info("="*60 + "\n")
    
    passed = 0
    failed = 0
    
    for test_name, status, expected in results:
        symbol = "✓" if expected else "✗"
        info(f"  {symbol} {test_name:20s} → {status:12s}\n")
        if expected:
            passed += 1
        else:
            failed += 1
    
    info("\n" + "-"*60 + "\n")
    info(f"  Tests pasados: {passed}/{len(results)}\n")
    info(f"  Tests fallidos: {failed}/{len(results)}\n")
    info("="*60 + "\n")

    # Cleanup
    info("\nLimpiando procesos iperf...\n")
    for h in [h1, h2, h3, h4]:
        h.cmd("pkill -9 iperf || true")
    
    net.stop()
    info("\n*** Tests completados ***\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 test_iperf.py <num_switches>")
        print("Ejemplo: sudo python3 test_iperf.py 4")
        sys.exit(1)
    
    n = int(sys.argv[1])
    if n < 2:
        print("La topología requiere al menos 2 switches")
        sys.exit(1)

    run_iperf_tests(n)
