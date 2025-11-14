#!/usr/bin/env python3
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

    info("Starting Mininet...\n")
    net.start()
    time.sleep(1)

    info("Getting hosts...\n")
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    # Forzar aprendizaje de MACs / flows
    info("Forzando aprendizaje inicial...\n")
    h1.cmd("ping -c1 10.0.0.2 >/dev/null 2>&1 || true")
    h2.cmd("ping -c1 10.0.0.3 >/dev/null 2>&1 || true")
    h3.cmd("ping -c1 10.0.0.4 >/dev/null 2>&1 || true")
    time.sleep(0.5)

    results = []

    info("\n==============================\n")
    info("      TEST REGLA 2\n")
    info("==============================\n")

    # TEST 2.1 — IPv4 UDP → DEBE BLOQUEARSE
    info("\nTEST 2.1: IPv4 + UDP (h1 → h4:5001) debe bloquearse\n")

    # Servidor UDP en h4
    h4.cmd("pkill -f 'udp_test' || true")
    server_code = (
        "import socket\n"
        "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.bind(('',5001))\n"
        "try:\n"
        "  data,addr=s.recvfrom(2048)\n"
        "  s.sendto(b'OK', addr)\n"
        "except: pass\n"
        "s.close()\n"
    )
    h4.cmd(f"python3 -u - <<'PY' >/tmp/srv5001.log 2>&1 &\n{server_code}\nPY")
    time.sleep(0.3)

    output = h1.cmd(
        "python3 -u - <<'PY'\n"
        "import socket\n"
        "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.settimeout(2)\n"
        "s.sendto(b'PING', ('10.0.0.4',5001))\n"
        "try:\n"
        "  data,addr=s.recvfrom(4096)\n"
        "  print(data.decode())\n"
        "except:\n"
        "  print('NO_REPLY')\n"
        "PY"
    )

    blocked = ("NO_REPLY" in output)
    results.append(("IPv4 UDP", blocked))
    info(f"Resultado: {'BLOCKED' if blocked else 'ALLOWED'} (output={output.strip()})\n")

    # TEST 2.2 — IPv6 UDP → DEBE BLOQUEARSE
    info("\nTEST 2.2: IPv6 + UDP (h1 → h4:5001) debe bloquearse\n")

    h1.cmd("ip -6 addr add fd00::1/64 dev h1-eth0 || true")
    h4.cmd("ip -6 addr add fd00::4/64 dev h4-eth0 || true")
    time.sleep(0.1)

    h4.cmd("pkill -f 'nc -u -6 -l 5001' || true")
    h4.cmd("rm -f /tmp/udp5001_v6.log")
    h4.cmd("nohup nc -u -6 -l 5001 >/tmp/udp5001_v6.log 2>&1 &")
    time.sleep(0.3)

    h1.cmd("echo 'TESTV6' | nc -u -6 -w2 fd00::4 5001 || true")
    time.sleep(0.3)

    received = h4.cmd("grep -q TESTV6 /tmp/udp5001_v6.log && echo OK || echo NO").strip()
    blocked = (received != "OK")
    results.append(("IPv6 UDP", blocked))
    info(f"Resultado: {'BLOCKED' if blocked else 'ALLOWED'} (received={received})\n")

    # TEST 2.3 — IPv4 TCP → DEBE PERMITIRSE
    info("\nTEST 2.3: IPv4 + TCP (h1 → h4:5001) debe PERMITIRSE\n")

    h4.cmd("pkill -f 'http.server' || true")
    h4.cmd("python3 -m http.server 5001 >/tmp/tcp5001.log 2>&1 &")
    time.sleep(0.4)

    output = h1.cmd("timeout 3 curl -s -I http://10.0.0.4:5001 || true")
    allowed = (output.strip() != "")
    results.append(("IPv4 TCP", allowed))
    info(f"Resultado: {'ALLOWED' if allowed else 'BLOCKED'} (output len={len(output)})\n")

    h4.cmd("pkill -f 'http.server' || true")

    # TEST 2.4 — IPv6 TCP → DEBE PERMITIRSE
    info("\nTEST 2.4: IPv6 + TCP (h1 → h4:5001) debe PERMITIRSE\n")

    h4.cmd("pkill -f 'http.server' || true")
    h4.cmd("ip -6 addr add fd00::4/64 dev h4-eth0 || true")
    h1.cmd("ip -6 addr add fd00::1/64 dev h1-eth0 || true")
    h4.cmd("python3 -m http.server 5001 --bind fd00::4 >/tmp/tcp5001_v6.log 2>&1 &")
    time.sleep(0.4)

    output = h1.cmd("timeout 3 curl -g -6 -s -I http://[fd00::4]:5001 || true")
    allowed = (output.strip() != "")
    results.append(("IPv6 TCP", allowed))
    info(f"Resultado: {'ALLOWED' if allowed else 'BLOCKED'} (output len={len(output)})\n")

    h4.cmd("pkill -f 'http.server' || true")

    # RESULTADOS FINALES
    info("\n==============================\n")
    info("      RESULTADOS REGLA 2\n")
    info("==============================\n")
    for name, ok in results:
        info(f" {name:12s} → {'OK' if ok else 'FAIL'}\n")

    net.stop()
    info("\n*** Tests completados ***\n")


if __name__ == "__main__":
    n = int(sys.argv[1])
    if n == None:
        print("Uso: python3 test_regla1.py <num_switches>")
        sys.exit(1)
    if n < 2:
        print("La topología requiere al menos 2 switches")
        sys.exit(1)

    run_tests(n)
